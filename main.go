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

// proxy is an HTTP/S proxy configurable via an HTTP API.
//
// It can be dynamically configured/queried at runtime by issuing requests to
// proxy specific paths using JSON.
//
// Supported configuration endpoints:
//
//   POST http://martian.proxy/configure
//
// sets the request and response modifier of the proxy; modifiers adhere to the
// following top-level JSON structure:
//
//   {
//     "package.Modifier": {
//       "scope": ["request", "response"],
//       "attribute 1": "value",
//       "attribute 2": "value"
//     }
//   }
//
// modifiers may be "stacked" to provide support for additional behaviors; for
// example, to add a "Martian-Test" header with the value "true" for requests
// with the domain "www.example.com" the JSON message would be:
//
//   {
//     "url.Filter": {
//       "scope": ["request"],
//       "host": "www.example.com",
//       "modifier": {
//         "header.Modifier": {
//           "name": "Martian-Test",
//           "value": "true"
//         }
//       }
//     }
//   }
//
// url.Filter parses the JSON object in the value of the "url.Filter" attribute;
// the "host" key tells the url.Filter to filter requests if the host explicitly
// matches "www.example.com"
//
// the "modifier" key within the "url.Filter" JSON object contains another
// modifier message of the type header.Modifier to run iff the filter passes
//
// groups may also be used to run multiple modifiers sequentially; for example to
// log requests and responses after adding the "Martian-Test" header to the
// request, but only when the host matches www.example.com:
//
//   {
//     "url.Filter": {
//       "host": "www.example.com",
//       "modifier": {
//         "fifo.Group": {
//           "modifiers": [
//             {
//               "header.Modifier": {
//                 "scope": ["request"],
//                 "name": "Martian-Test",
//                 "value": "true"
//               }
//             },
//             {
//               "log.Logger": { }
//             }
//           ]
//         }
//       }
//     }
//   }
//
// modifiers are designed to be composed together in ways that allow the user to
// write a single JSON structure to accomplish a variety of functionality
//
//   GET http://martian.proxy/verify
//
// retrieves the verifications errors as JSON with the following structure:
//
//   {
//     "errors": [
//       {
//         "message": "request(url) verification failure"
//       },
//       {
//         "message": "response(url) verification failure"
//       }
//     ]
//   }
//
// verifiers also adhere to the modifier interface and thus can be included in the
// modifier configuration request; for example, to verify that all requests to
// "www.example.com" are sent over HTTPS send the following JSON to the
// configuration endpoint:
//
//   {
//     "url.Filter": {
//       "scope": ["request"],
//       "host": "www.example.com",
//       "modifier": {
//         "url.Verifier": {
//           "scope": ["request"],
//           "scheme": "https"
//         }
//       }
//     }
//   }
//
// sending a request to "http://martian.proxy/verify" will then return errors from the url.Verifier
//
//   POST http://martian.proxy/verify/reset
//
// resets the verifiers to their initial state; note some verifiers may start in
// a failure state (e.g., pingback.Verifier is failed if no requests have been
// seen by the proxy)
//
//   GET http://martian.proxy/authority.cer
//
// prompts the user to install the CA certificate used by the proxy if MITM is enabled
//
//   GET http://martian.proxy/logs
//
// retrieves the HAR logs for all requests and responses seen by the proxy if
// the HAR flag is enabled
//
//   DELETE http://martian.proxy/logs/reset
//
// reset the in-memory HAR log; note that the log will grow unbounded unless it
// is periodically reset
//
// passing the -cors flag will enable CORS support for the endpoints so that they
// may be called via AJAX
//
// Sending a sigint will cause the proxy to stop receiving new connections,
// finish processing any inflight requests, and close existing connections without
// reading anymore requests from them.
//
// The flags are:
//   -addr=":8080"
//     host:port of the proxy
//   -api-addr=":8181"
//     host:port of the proxy API
//   -tls-addr=":4443"
//     host:port of the proxy over TLS
//   -api="martian.proxy"
//     hostname that can be used to reference the configuration API when
//     configuring through the proxy
//   -cert=""
//     PEM encoded X.509 CA certificate; if set, it will be set as the
//     issuer for dynamically-generated certificates during man-in-the-middle
//   -key=""
//     PEM encoded private key of cert (RSA or ECDSA); if set, the key will be used
//     to sign dynamically-generated certificates during man-in-the-middle
//   -generate-ca-cert=false
//     generates a CA certificate and private key to use for man-in-the-middle;
//     the certificate is only valid while the proxy is running and will be
//     discarded on shutdown
//   -organization="Martian Proxy"
//     organization name set on the dynamically-generated certificates during
//     man-in-the-middle
//   -validity="1h"
//     window of time around the time of request that the dynamically-generated
//     certificate is valid for; the duration is set such that the total valid
//     timeframe is double the value of validity (1h before & 1h after)
//   -cors=false
//     allow the proxy to be configured via CORS requests; such as when
//     configuring the proxy via AJAX
//   -har=false
//     enable logging endpoints for retrieving full request/response logs in
//     HAR format.
//   -traffic-shaping=false
//     enable traffic shaping endpoints for simulating latency and constrained
//     bandwidth conditions (e.g. mobile, exotic network infrastructure, the
//     90's)
//   -skip-tls-verify=false
//     skip TLS server verification; insecure and intended for testing only
//   -v=0
//     log level for console logs; defaults to error only.
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

	"mproxy/har"

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
