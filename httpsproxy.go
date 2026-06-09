// https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c
//https://gist.github.com/wwek/41790cbef2e33b6065eaea688ea54760

// #!/usr/bin/env bash
// case `uname -s` in
//     Linux*)     sslConfig=/etc/ssl/openssl.cnf;;
//     Darwin*)    sslConfig=/System/Library/OpenSSL/openssl.cnf;;
// esac
// openssl req \
//     -newkey rsa:2048 \
//     -x509 \
//     -nodes \
//     -keyout server.key \
//     -new \
//     -out server.pem \
//     -subj /CN=localhost \
//     -reqexts SAN \
//     -extensions SAN \
//     -config <(cat $sslConfig \
//         <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
//     -sha256 \
//     -days 3650

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var version = "2.2.1"
var logger *log.Logger

func init() {
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "httpsproxy")
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %v", err)
	}
	logger = log.New(sysLogger, "", 0)
	logger.Printf("Version: %s", version)
	logger.Printf("Intialized logger")
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	logger.Printf("Received PROXY request: %s %s from %s ", r.Method, r.RequestURI, r.RemoteAddr)
	//dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	dest_conn, err := net.DialTimeout("tcp", "10.11.12.5:2222", 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {

	//log the http request host
	logger.Printf("Request to %s -> %s ", req.Host, req.RequestURI)

	if req.TLS == nil {
		// Check if host contains -nafpaktias
		if strings.Contains(req.Host, "-nafpaktias") {
			logger.Printf("Redirecting request to 10.11.12.24")

			// Create a reverse proxy to redirect to 10.11.12.24
			nafpaktiasURL := &url.URL{
				Scheme: "http",
				Host:   "10.11.12.24",
			}
			proxy := httputil.NewSingleHostReverseProxy(nafpaktiasURL)
			//proxy.Transport = &http.Transport{
			//	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			//}
			proxy.ServeHTTP(w, req)
			return
		}
	} else {

		if strings.Contains(req.Host, "-nafpaktias") {
			logger.Printf("Redirecting request to https to http")

			// Build the redirect URL
			redirectURL := fmt.Sprintf("http://%s%s", req.Host, req.RequestURI)
			http.Redirect(w, req, redirectURL, http.StatusMovedPermanently) // 301
			return
		}

		// Check if host contains vega.rugad.eu
		if strings.Contains(req.Host, "vega.rugad.eu") {
			logger.Printf("Redirecting request to vega")

			// Create a reverse proxy using the original request's host (no rewrite)
			vegaURL := &url.URL{
				Scheme: "https",
				Host:   req.Host,
			}
			proxy := httputil.NewSingleHostReverseProxy(vegaURL)
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			proxy.ServeHTTP(w, req)
			return
		}

		// Check the request URI
		if strings.HasPrefix(req.RequestURI, "/start-the-secret-web-ssh") ||
			strings.HasPrefix(req.RequestURI, "/static/css/") ||
			strings.HasPrefix(req.RequestURI, "/static/js/") {

			dest := "https://10.11.12.5:4433"
			targetURL, _ := url.Parse(dest)

			// Create a reverse proxy for redirection with HTTPS settings
			proxy := httputil.NewSingleHostReverseProxy(targetURL)

			// Configure the proxy to skip certificate verification (only for local development)
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			// Use the reverse proxy to forward the request
			req.URL.Path = strings.TrimPrefix(req.URL.Path, "/start-the-secret-web-ssh")
			proxy.ServeHTTP(w, req)
			return
		}

	}
	http.Error(w, "go away", http.StatusForbidden)
	logger.Printf("Request Denied: %s %s from %s", req.Method, req.RequestURI, req.RemoteAddr)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	var pemPath string
	flag.StringVar(&pemPath, "pem", "server.crt", "path to pem file")
	var keyPath string
	flag.StringVar(&keyPath, "key", "server.key", "path to key file")
	flag.Parse()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	})

	// HTTPS server on port 61200
	httpsServer := &http.Server{
		Addr:    ":61200",
		Handler: handler,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:     logger,
	}

	// HTTP server on port 61201
	httpServer := &http.Server{
		Addr:     ":61201",
		Handler:  handler,
		ErrorLog: logger,
	}

	// Start HTTP server in a goroutine
	go func() {
		logger.Print("Starting HTTP server on :61201")
		if err := httpServer.ListenAndServe(); err != nil {
			logger.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server (blocking)
	logger.Print("Starting HTTPS server on :61200")
	if err := httpsServer.ListenAndServeTLS(pemPath, keyPath); err != nil {
		logger.Printf("HTTPS server error: %v", err)
	}
}
