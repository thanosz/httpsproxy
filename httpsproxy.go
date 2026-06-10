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
	"context"
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
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

var version = "3.0.0"
var logger *log.Logger
var config Config
var configMutex sync.RWMutex
var configPath string
var currentServer *http.Server

// Config structures
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Syslog  SyslogConfig  `yaml:"syslog"`
	Proxy   ProxyConfig   `yaml:"proxy"`
	Routes  []RouteConfig `yaml:"routes"`
	Default DefaultConfig `yaml:"default"`
}

type ServerConfig struct {
	Port     int    `yaml:"port"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type SyslogConfig struct {
	Priority string `yaml:"priority"`
	Tag      string `yaml:"tag"`
}

type ProxyConfig struct {
	DialTimeout       int    `yaml:"dial_timeout"`
	TunnelDestination string `yaml:"tunnel_destination"`
}

type RouteConfig struct {
	Name               string   `yaml:"name"`
	HostContains       string   `yaml:"host_contains"`
	URIPrefixes        []string `yaml:"uri_prefixes"`
	TargetScheme       string   `yaml:"target_scheme"`
	TargetHost         string   `yaml:"target_host"`
	TargetURL          string   `yaml:"target_url"`
	UseOriginalHost    bool     `yaml:"use_original_host"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify"`
	SetForwardedProto  bool     `yaml:"set_forwarded_proto"`
	StripPrefix        string   `yaml:"strip_prefix"`
}

type DefaultConfig struct {
	DeniedStatus  int    `yaml:"denied_status"`
	DeniedMessage string `yaml:"denied_message"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

func getConfig() Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config
}

func setConfig(cfg Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	config = cfg
}

func startHTTPSServer(handler http.Handler, cfg Config) *http.Server {
	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      handler,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:     logger,
	}

	logger.Printf("Starting HTTPS server on %s", serverAddr)
	go func() {
		if err := server.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile); err != nil && err != http.ErrServerClosed {
			logger.Printf("HTTPS server error: %v", err)
			os.Exit(1)
		}
	}()

	return server
}

func stopHTTPSServer(server *http.Server) error {
	if server == nil {
		return nil
	}

	logger.Printf("Shutting down HTTPS server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Printf("Error shutting down server: %v", err)
		return err
	}

	logger.Printf("Server shut down successfully")
	return nil
}

func reloadConfig(handler http.Handler) error {
	logger.Printf("Reloading configuration from %s", configPath)

	cfg, err := loadConfig(configPath)
	if err != nil {
		logger.Printf("Failed to reload configuration: %v", err)
		return err
	}

	setConfig(*cfg)
	logger.Printf("Configuration reloaded successfully")
	return nil
}

func setupSignalHandler(handler http.Handler) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			sig := <-sigChan
			logger.Printf("Received signal: %v", sig)

			switch sig {
			case syscall.SIGHUP:
				if err := reloadConfig(handler); err != nil {
					logger.Printf("Configuration reload failed: %v", err)
					return
				}
				stopHTTPSServer(currentServer)
				currentCfg := getConfig()
				currentServer = startHTTPSServer(handler, currentCfg)
			case syscall.SIGTERM:
				logger.Printf("Shutting down...")
				stopHTTPSServer(currentServer)
				os.Exit(0)
			}
		}
	}()

	logger.Printf("Signal handler initialized (SIGHUP=reload)")
}

func initLogger(tag string) {
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %v", err)
	}
	logger = log.New(sysLogger, "", 0)
	logger.Printf("Version: %s", version)
	logger.Printf("Initialized logger")
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	logger.Printf("Received PROXY request: %s %s from %s ", r.Method, r.RequestURI, r.RemoteAddr)
	cfg := getConfig()
	timeout := time.Duration(cfg.Proxy.DialTimeout) * time.Second

	// Determine destination: use configured tunnel_destination or the requested host
	destination := cfg.Proxy.TunnelDestination
	if destination == "" {
		destination = r.Host
		logger.Printf("No tunnel_destination configured, using requested host: %s", destination)
	}

	dest_conn, err := net.DialTimeout("tcp", destination, timeout)
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
	cfg := getConfig()

	// Check each route in configuration
	for _, route := range cfg.Routes {
		// Check host-based routes
		if route.HostContains != "" && strings.Contains(req.Host, route.HostContains) {
			logger.Printf("Accepted: %s %s%s from %s", req.Method, req.Host, req.RequestURI, req.RemoteAddr)

			var targetURL *url.URL
			if route.UseOriginalHost {
				targetURL = &url.URL{
					Scheme: route.TargetScheme,
					Host:   req.Host,
				}
			} else {
				targetURL = &url.URL{
					Scheme: route.TargetScheme,
					Host:   route.TargetHost,
				}
			}

			proxy := httputil.NewSingleHostReverseProxy(targetURL)
			if route.InsecureSkipVerify {
				proxy.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}
			if route.SetForwardedProto {
				req.Header.Set("X-Forwarded-Proto", "https")
			}
			proxy.ServeHTTP(w, req)
			return
		}

		// Check URI prefix-based routes
		if len(route.URIPrefixes) > 0 {
			for _, prefix := range route.URIPrefixes {
				if strings.HasPrefix(req.RequestURI, prefix) {
					logger.Printf("Accepted: %s %s%s from %s", req.Method, req.Host, req.RequestURI, req.RemoteAddr)

					targetURL, _ := url.Parse(route.TargetURL)
					proxy := httputil.NewSingleHostReverseProxy(targetURL)

					if route.InsecureSkipVerify {
						proxy.Transport = &http.Transport{
							TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						}
					}

					// Strip prefix if configured
					if route.StripPrefix != "" {
						req.URL.Path = strings.TrimPrefix(req.URL.Path, route.StripPrefix)
					}

					proxy.ServeHTTP(w, req)
					return
				}
			}
		}
	}

	// No route matched - deny request
	http.Error(w, cfg.Default.DeniedMessage, cfg.Default.DeniedStatus)
	logger.Printf("Denied: %s %s%s from %s", req.Method, req.Host, req.RequestURI, req.RemoteAddr)
}

func main() {
	flag.StringVar(&configPath, "config", "config.yaml", "path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	setConfig(*cfg)

	// Initialize logger with config
	currentCfg := getConfig()
	initLogger(currentCfg.Syslog.Tag)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	})

	// Setup signal handler for config reload
	setupSignalHandler(handler)

	// Start HTTPS server
	currentCfg = getConfig()
	currentServer = startHTTPSServer(handler, currentCfg)

	// Keep main goroutine alive
	select {}
}
