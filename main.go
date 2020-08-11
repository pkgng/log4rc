// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"log4rc/har"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/fifo"
	"github.com/google/martian/v3/httpspec"
	"github.com/google/martian/v3/martianhttp"
	"github.com/google/martian/v3/martianlog"
	"github.com/google/martian/v3/mitm"
	"github.com/google/martian/v3/servemux"

	_ "github.com/google/martian/v3/body"
	_ "github.com/google/martian/v3/cookie"
	_ "github.com/google/martian/v3/failure"
	_ "github.com/google/martian/v3/martianurl"
	_ "github.com/google/martian/v3/method"
	_ "github.com/google/martian/v3/pingback"
	_ "github.com/google/martian/v3/port"
	_ "github.com/google/martian/v3/priority"
	_ "github.com/google/martian/v3/querystring"
	_ "github.com/google/martian/v3/skip"
	_ "github.com/google/martian/v3/stash"
	_ "github.com/google/martian/v3/static"
	_ "github.com/google/martian/v3/status"
)

var (
	addr             = flag.String("addr", ":50080", "host:port of the proxy")
	sign             = flag.String("sign", "reqLib", "organization name for MITM certificates And via Header on Request for Loop Dectect")
	skipTLSVerify    = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	mlog             = flag.String("log", "./martian.log", "full path of the log file")
	logSyncDuration  = flag.Int("log-sync-duration", 2, "time Duration of sync log from mem to disk")
	skipConnectLog   = flag.Bool("skip-connect-log", true, "skip connect log")
	dialerTimeout    = flag.Int("dialer-timeout", 30, "timeout of dailing a connect")
	disableKeepalive = flag.Bool("disable-keepalive", false, "if disable keepalive")
	keepaliveDuraion = flag.Int("keepalive-duration", 30, "time Duration of keepAlive")
)

func main() {
	p := martian.NewProxy()
	defer p.Close()

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   time.Duration(*dialerTimeout) * time.Second,
			KeepAlive: time.Duration(*keepaliveDuraion) * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *skipTLSVerify,
		},
		DisableKeepAlives: *disableKeepalive,
	}
	p.SetRoundTripper(tr)

	mux := http.NewServeMux()

	{
		var x509c *x509.Certificate
		var priv interface{}

		var err error
		x509c, priv, err = mitm.NewAuthority(*sign, *sign, 30*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}

		if x509c != nil && priv != nil {
			mc, err := mitm.NewConfig(x509c, priv)
			if err != nil {
				log.Fatal(err)
			}

			mc.SetValidity(time.Hour * 3)
			mc.SetOrganization(*sign)
			mc.SkipTLSVerify(*skipTLSVerify)

			p.SetMITM(mc)
		}
	}

	stack, fg := httpspec.NewStack(*sign)

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)

	p.SetRequestModifier(topg)
	p.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)

	if *mlog != "" {
		hl := har.NewLogger()
		muxf := servemux.NewFilter(mux)
		// Only append to HAR logs when the requests are not API requests,
		// that is, they are not matched in http.DefaultServeMux
		muxf.RequestWhenFalse(hl)
		muxf.ResponseWhenFalse(hl)

		stack.AddRequestModifier(muxf)
		stack.AddResponseModifier(muxf)

		go harLogSync(hl, *mlog)
	}

	logger := martianlog.NewLogger()
	logger.SetDecode(true)

	stack.AddRequestModifier(logger)
	stack.AddResponseModifier(logger)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("martian: starting proxy on %s", l.Addr().String())

	go p.Serve(l)

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, os.Kill)

	<-sigc

	log.Println("martian: shutting down")
}

func init() {
	martian.Init()
}

func harLogSync(har *har.Logger, fname string) {
	end := []byte{'\n'}

	for {
		time.Sleep(time.Duration(*logSyncDuration) * time.Second)

		f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatal(err)
			continue
		}

		for _, e := range har.ExportAndReset().Log.Entries {
			if *skipConnectLog {
				if e.Request.Method == "CONNECT" {
					continue
				}
			}

			jsonEntry, err := json.Marshal(e)
			if err != nil {
				log.Fatal(err)
				continue
			}

			f.Write(jsonEntry)
			f.Write(end)
		}

		f.Close()
	}
}
