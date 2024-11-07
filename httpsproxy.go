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
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

func handleTunneling(w http.ResponseWriter, r *http.Request) {
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
	http.Error(w, "go away", http.StatusForbidden)
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
	var proto string
	flag.StringVar(&proto, "proto", "https", "Proxy protocol (http or https)")
	flag.Parse()
	if proto != "http" && proto != "https" {
		log.Fatal("Protocol must be either http or https")
	}
	server := &http.Server{
		Addr: ":61200",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if proto == "http" {
		log.Fatal(server.ListenAndServe())
	} else {
		log.Fatal(server.ListenAndServeTLS(pemPath, keyPath))
	}
}
