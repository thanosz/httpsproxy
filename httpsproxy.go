// httpsproxy — a TLS-terminating reverse proxy with brute-force detection.
//
// It listens on a single HTTPS port, routes requests to backend services based
// on the Host header, and automatically bans source IPs that exhibit abusive
// behaviour (TLS scanning, connection bursts, or repeated denied requests).
//
// TLS certificate generation (self-signed, for testing):
//
//	case `uname -s` in
//	    Linux*)  sslConfig=/etc/ssl/openssl.cnf;;
//	    Darwin*) sslConfig=/System/Library/OpenSSL/openssl.cnf;;
//	esac
//	openssl req -newkey rsa:2048 -x509 -nodes \
//	    -keyout server.key -new -out server.pem \
//	    -subj /CN=localhost \
//	    -reqexts SAN -extensions SAN \
//	    -config <(cat $sslConfig <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
//	    -sha256 -days 3650

package main

import (
	"bufio"
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

	proxyproto "github.com/pires/go-proxyproto"
	"gopkg.in/yaml.v3"
)

var version = "4.0.0"

// proxyProtoDialer dials an upstream backend and immediately writes a HAProxy
// PROXY protocol v2 header so the backend can see the original client address.
// It is used when a route has send_proxy_protocol: true.
type proxyProtoDialer struct {
	clientAddr net.Addr // original client TCP address (ip:port)
}

// logger writes to syslog. Initialised in initLogger before any server starts.
var logger *log.Logger

// config is the live configuration. Always read via getConfig() and written
// via setConfig() to ensure thread safety across concurrent request handlers.
var config Config
var configMutex sync.RWMutex

// configPath is the path to the YAML config file, set by the -config flag.
var configPath string

// currentServer is the running *http.Server. Replaced on SIGHUP reload.
var currentServer *http.Server

// Two independent counters run per source IP. Either counter reaching its
// threshold immediately bans the IP for ban_duration_seconds. The counters
// never interact with each other.
//
//  Counter 1 — TLS errors (optional, default: 3, set to 0 to disable)
//    Counts failed TLS handshakes (EOF, bad version, unknown cipher).
//    Threshold: tls_ban_threshold  (default: 3, 0 = disabled)
//    Window:    tls_window_seconds (default: 5 s)
//    Example: 3 TLS probes in 5 s → banned.
//
//  Counter 2 — HTTP error rate (optional, disabled by default)
//    Counts HTTP requests that returned a non-200 response within a sliding
//    window. 200 responses are not counted — a legitimate client browsing
//    a site mostly receives 200s, while a scanner receives a stream of
//    403s, 404s, or 5xxs.
//    Threshold: http_ban_threshold (default: 0 = disabled)
//    Window:    http_window_seconds (default: 10 s)
//    Example: 10 non-200 responses in 10 s → banned.

// eventType classifies an observable network event.
type eventType int

const (
	// eventTLSError is emitted when a TLS handshake fails (from tlsErrorWriter).
	eventTLSError eventType = iota

	// eventRequest is emitted on every HTTP request, regardless of outcome.
	// It feeds the request-rate counter.
	eventRequest
)

// ipState holds the per-IP counters for both independent ban checks.
// The embedded mutex must be held for all reads and writes.
type ipState struct {
	mu sync.Mutex

	// windowStart marks the beginning of the current counting window.
	// Both counters reset together when the window expires.
	windowStart time.Time

	// tlsErrors counts failed TLS handshakes in the current window.
	tlsErrors int

	// recentRequests holds timestamps of non-200 HTTP responses for the
	// rate-limit sub-window (only used when http_ban_threshold > 0).
	recentRequests []time.Time

	// bannedUntil is when the current ban expires. Zero means not banned.
	bannedUntil time.Time
}

// banTracker maps source IP strings to their *ipState. sync.Map is used
// because access is highly concurrent (one goroutine per request) and the
// map is read far more often than it is written.
var banTracker sync.Map // key: string IP, value: *ipState

// Config is the top-level configuration structure. It is loaded from a YAML
// file on startup and re-loaded atomically on SIGHUP.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Syslog   SyslogConfig   `yaml:"syslog"`
	Proxy    ProxyConfig    `yaml:"proxy"`
	Routes   []RouteConfig  `yaml:"routes"`
	Default  DefaultConfig  `yaml:"default"`
	Security SecurityConfig `yaml:"security"`
}

// ServerConfig holds TLS listener settings.
type ServerConfig struct {
	Port     int    `yaml:"port"`      // TCP port to listen on (e.g. 443 or 8443)
	CertFile string `yaml:"cert_file"` // path to PEM-encoded TLS certificate
	KeyFile  string `yaml:"key_file"`  // path to PEM-encoded private key
}

// SyslogConfig controls the syslog destination for all log output.
type SyslogConfig struct {
	Priority string `yaml:"priority"` // syslog facility+level, e.g. "LOG_INFO|LOG_DAEMON"
	Tag      string `yaml:"tag"`      // syslog program identifier, e.g. "httpsproxy"
}

// ProxyConfig holds settings that apply to all outbound connections.
type ProxyConfig struct {
	DialTimeout       int    `yaml:"dial_timeout"`       // seconds before an upstream dial times out
	TunnelDestination string `yaml:"tunnel_destination"` // fixed target for CONNECT tunnels; if empty, uses r.Host
}

// RouteConfig defines a single routing rule. Routes are evaluated in order;
// the first matching route wins.
type RouteConfig struct {
	Name              string `yaml:"name"`                // human-readable label for logging
	HostContains      string `yaml:"host_contains"`       // substring matched against the HTTP Host header
	TLSTermination    bool   `yaml:"tls_termination"`     // true → proxy to backend over plain HTTP (proxy terminates TLS)
	TargetHost        string `yaml:"target_host"`         // backend address, e.g. "10.0.0.1:8080"
	UseOriginalHost   bool   `yaml:"use_original_host"`   // true → forward using the client's Host header unchanged
	RedirectURL       string `yaml:"redirect_url"`        // if set, issue a 301 redirect to this URL instead of proxying
	SendProxyProtocol bool   `yaml:"send_proxy_protocol"` // true → prepend HAProxy PROXY protocol v2 header to backend connection
}

// DefaultConfig controls the response sent when no route matches.
type DefaultConfig struct {
	DeniedStatus  int    `yaml:"denied_status"`  // HTTP status code, e.g. 403
	DeniedMessage string `yaml:"denied_message"` // response body text
}

// SecurityConfig controls the brute-force detection and IP ban behaviour.
// All fields are optional — safe defaults are applied when a field is omitted.
//
// Two independent ban rules, each firing on its own:
//
//  1. TLS errors:    ban after tls_ban_threshold failed handshakes in tls_window_seconds
//     (set to 0 to disable)
//  2. Request rate:  ban after http_ban_threshold non-200 HTTP responses
//     in http_window_seconds (set to 0 to disable; default is disabled)
type SecurityConfig struct {
	// BanDurationSeconds is how long a banned IP is blocked.
	// Default: 300 (5 minutes).
	BanDurationSeconds int `yaml:"ban_duration_seconds"`

	// WindowSeconds is the shared outer rolling time window. When it expires,
	// both the TLS-error counter and the recentRequests slice are reset.
	// Default: 5 seconds.
	WindowSeconds int `yaml:"tls_window_seconds"`

	// TLSBanThreshold is the number of failed TLS handshakes within
	// tls_window_seconds that triggers a ban.
	// Set to 0 to disable this rule entirely. Default: 3.
	TLSBanThreshold int `yaml:"tls_ban_threshold"`

	// RateLimitThreshold is the number of HTTP requests within
	// http_window_seconds that triggers a ban. Counts every request
	// regardless of whether it was accepted or denied.
	// Set to 0 to disable this rule entirely. Default: 0 (disabled).
	RateLimitThreshold int `yaml:"http_ban_threshold"`

	// RateLimitWindowSeconds is the sliding window for the request-rate rule.
	// Only used when http_ban_threshold > 0. Default: 10 seconds.
	RateLimitWindowSeconds int `yaml:"http_window_seconds"`
}

// applyDefaults fills any zero-valued SecurityConfig fields with safe defaults.
// This allows existing config.yaml files without a security: block to work
// without modification.
func (s *SecurityConfig) applyDefaults() {
	if s.BanDurationSeconds == 0 {
		s.BanDurationSeconds = 300
	}
	if s.WindowSeconds == 0 {
		s.WindowSeconds = 5
	}

	// RateLimitThreshold defaults to 0 (disabled) intentionally.
	if s.RateLimitWindowSeconds == 0 {
		s.RateLimitWindowSeconds = 10
	}
}

// loadConfig reads and parses the YAML file at path. It applies SecurityConfig
// defaults after unmarshalling so callers always receive a fully populated Config.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.Security.applyDefaults()
	return &cfg, nil
}

// getConfig returns a consistent snapshot of the current configuration.
// It acquires a read lock so concurrent request handlers never observe a
// partially written config during a SIGHUP reload.
func getConfig() Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return config
}

// setConfig atomically replaces the live configuration. Called on startup and
// on every successful SIGHUP reload. Acquires a full write lock briefly.
func setConfig(cfg Config) {
	configMutex.Lock()
	defer configMutex.Unlock()
	config = cfg
}

// getOrCreateState returns the existing ipState for ip, or atomically creates
// and stores a new one. LoadOrStore guarantees only one *ipState exists per IP
// even under concurrent first-access from multiple goroutines.
func getOrCreateState(ip string) *ipState {
	s := &ipState{windowStart: time.Now()}
	v, _ := banTracker.LoadOrStore(ip, s)
	return v.(*ipState)
}

// banListener wraps a net.Listener and drops connections from banned IPs
// before they reach the TLS layer. Accept loops until a non-banned connection
// arrives or the underlying listener returns an error.
type banListener struct {
	net.Listener
}

func (l *banListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err != nil || isBanned(ip) {
			if err == nil {
				logger.Printf("%s == BANNED ==", ip)
			}
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// DialContext establishes a TCP connection to addr and prepends the PROXY
// protocol header before any application data is exchanged.
func (d *proxyProtoDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	hdr := proxyproto.HeaderProxyFromAddrs(2, d.clientAddr, conn.RemoteAddr())
	if _, err := hdr.WriteTo(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// startHTTPSServer starts the HTTPS listener in a background goroutine and
// returns the *http.Server immediately so the caller can stop it later.
//
// Listener stack (innermost first):
//
//	http.Server.Serve
//	  └── tls.NewListener     — terminates TLS, hands *tls.Conn to http.Server
//	        └── banListener        — drops banned IPs before TLS handshake
//	              └── proxyproto.Listener — strips HAProxy PROXY protocol headers
//	                    └── net.Listener  — raw TCP accept
//
// server.ErrorLog is wired to tlsErrorWriter so TLS handshake failures are
// intercepted and scored by the ban tracker before reaching syslog.
func startHTTPSServer(handler http.Handler, cfg Config) *http.Server {
	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)

	// Wrap the syslog writer so TLS errors feed the ban tracker.
	errLog := log.New(&tlsErrorWriter{underlying: logger.Writer()}, "", 0)

	server := &http.Server{
		Addr:    serverAddr,
		Handler: handler,
		// Setting TLSNextProto to a non-nil empty map disables HTTP/2, keeping
		// the server in HTTP/1.1-only mode which this proxy is designed for.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ErrorLog:     errLog,
	}

	logger.Printf("Starting HTTPS server on %s", serverAddr)
	go func() {
		ln, err := net.Listen("tcp", serverAddr)
		if err != nil {
			logger.Printf("HTTPS server listen error: %v", err)
			os.Exit(1)
		}

		// proxyproto.Listener transparently reads and strips the HAProxy PROXY
		// protocol header (v1 or v2) when present, then exposes the real client
		// address via conn.RemoteAddr(). Connections without a PROXY header are
		// passed through unchanged.
		ln = &proxyproto.Listener{Listener: ln}

		// banListener closes connections from banned IPs before the TLS
		// handshake begins, avoiding crypto overhead for known bad actors.
		ln = &banListener{Listener: ln}

		tlsCfg, err := tlsConfig(cfg)
		if err != nil {
			logger.Printf("HTTPS server TLS config error: %v", err)
			os.Exit(1)
		}

		if err := server.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
			logger.Printf("HTTPS server error: %v", err)
			os.Exit(1)
		}
	}()

	return server
}

// tlsConfig loads the certificate key pair from disk and returns a minimal
// tls.Config. HTTP/1.1 is the only advertised protocol (NextProtos) to match
// the server's TLSNextProto setting.
func tlsConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// stopHTTPSServer performs a graceful shutdown with a 5-second deadline.
// In-flight requests are allowed to complete; new connections are rejected.
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

// reloadConfig re-reads the config file and atomically updates the live config.
// Called from the SIGHUP handler. The running server is restarted by the
// signal handler after this function returns.
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

// setupSignalHandler listens for OS signals in a background goroutine:
//
//   - SIGHUP  — reload config from disk and restart the HTTP server.
//     Ban tracker state is preserved across reloads because it lives in
//     process memory and the main goroutine is never interrupted.
//   - SIGTERM — graceful shutdown.
//   - SIGINT  — graceful shutdown (Ctrl-C in interactive use).
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

// initLogger connects to the local syslog daemon and sets the global logger.
// All subsequent log output from every goroutine goes through this logger.
func initLogger(tag string) {
	sysLogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %v", err)
	}
	logger = log.New(sysLogger, "", 0)
	logger.Printf("Version: %s", version)
	logger.Printf("Initialized logger")
}

// handleTunneling handles HTTP CONNECT requests by establishing a raw TCP
// tunnel between the client and the destination host.
//
// If proxy.tunnel_destination is set in config, all CONNECT requests are
// directed there regardless of the requested host. This is used to force all
// tunneled traffic to a specific backend (e.g. an SSH bastion). If the option
// is empty, the destination from the CONNECT request line (r.Host) is used.
//
// Once the upstream connection is established and the connection is hijacked
// from the HTTP server, two goroutines copy bytes bidirectionally until both
// sides close.
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig()
	timeout := time.Duration(cfg.Proxy.DialTimeout) * time.Second

	// Determine destination: use configured tunnel_destination or the requested host.
	destination := cfg.Proxy.TunnelDestination
	if destination == "" {
		destination = r.Host
		logger.Printf("No tunnel_destination configured, using requested host: %s", destination)
	}

	logger.Printf("%s PROXY request=%s %s redirecting to %s", r.RemoteAddr, r.Method, r.RequestURI, destination)

	dest_conn, err := net.DialTimeout("tcp", destination, timeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Signal the client that the tunnel is open before hijacking.
	w.WriteHeader(http.StatusOK)

	// Hijack takes ownership of the raw TCP connection from the HTTP server.
	// After this point the http.ResponseWriter must not be used.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		// Header already sent; logging is the only recourse.
		logger.Printf("%s PROXY hijack not supported", r.RemoteAddr)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		// Header already sent; logging is the only recourse.
		logger.Printf("%s PROXY hijack error: %v", r.RemoteAddr, err)
		return
	}
	// Bidirectional byte copy. Each goroutine closes its writer when the
	// corresponding reader reaches EOF, tearing down both sides cleanly.
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

// transfer copies all bytes from source to destination, then closes both.
// Used for the bidirectional tunnel in handleTunneling.
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

// handleHTTP handles all non-CONNECT HTTP requests. It walks the configured
// route list in order and applies the first matching rule.
//
// Matching: a route matches when its host_contains value is a non-empty
// substring of the request's Host header.
//
// For a matched route:
//   - If redirect_url is set, issue a 301 redirect and return.
//   - Otherwise, build a target URL and reverse-proxy the request.
//     When tls_termination is true the proxy speaks plain HTTP to the backend
//     and sets X-Forwarded-Proto: https so the backend knows the original
//     scheme. When use_original_host is true the backend receives the client's
//     Host header unchanged instead of route.TargetHost.
//     When send_proxy_protocol is true a HAProxy PROXY v2 header is prepended
//     via proxyProtoDialer so the backend sees the real client IP.
//
// If no route matches, the request is denied with the configured status/message.
func handleHTTP(w http.ResponseWriter, req *http.Request) {
	cfg := getConfig()

	for _, route := range cfg.Routes {
		if route.HostContains != "" && strings.Contains(req.Host, route.HostContains) {
			// Route matched.

			if route.RedirectURL != "" {
				//logger.Printf("%s (REDIRECT) request=%s %s%s to %s", req.RemoteAddr, req.Method, req.Host, req.RequestURI, route.RedirectURL)
				http.Redirect(w, req, route.RedirectURL, http.StatusMovedPermanently)
				return
			}

			// When tls_termination is true this proxy terminates TLS and talks
			// plain HTTP to the backend. Set X-Forwarded-Proto so the backend
			// can reconstruct the original scheme if needed.
			scheme := "https"
			if route.TLSTermination {
				scheme = "http"
				req.Header.Set("X-Forwarded-Proto", "https")
			}

			var targetURL *url.URL
			if route.UseOriginalHost {
				// Preserve the client's Host header; the backend is addressed
				// by the same hostname the client used.
				targetURL = &url.URL{Scheme: scheme, Host: req.Host}
			} else {
				targetURL = &url.URL{Scheme: scheme, Host: route.TargetHost}
			}
			//logger.Printf("%s (ACCEPT) request=%s %s%s redirecting to %s", req.RemoteAddr, req.Method, req.Host, req.RequestURI, targetURL.Host)

			proxy := httputil.NewSingleHostReverseProxy(targetURL)
			transport := &http.Transport{
				// InsecureSkipVerify is intentional here: this proxy often
				// sits in front of backends with self-signed certificates on
				// an internal network. The TLS connection to the backend is
				// separate from the client-facing TLS which is fully verified.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			if route.SendProxyProtocol {
				// Replace the dialer so every backend connection begins with a
				// PROXY protocol header advertising the original client address.
				if tcpAddr, err := net.ResolveTCPAddr("tcp", req.RemoteAddr); err == nil {
					transport.DialContext = (&proxyProtoDialer{clientAddr: tcpAddr}).DialContext
				}
			}
			proxy.Transport = transport
			proxy.ServeHTTP(w, req)
			return
		}
	}

	// No route matched — deny the request.
	http.Error(w, cfg.Default.DeniedMessage, cfg.Default.DeniedStatus)
	//logger.Printf("%s (DENY)  request=%s %s%s", req.RemoteAddr, req.Method, req.Host, req.RequestURI)
}

// statusRecorder wraps http.ResponseWriter to capture the HTTP status code
// sent by the inner handler so it can be included in the access log.
//
// statusCode is initialised to 200. It reflects the actual code sent:
//   - If the handler calls WriteHeader(code) explicitly, statusCode is updated.
//   - If the handler writes a body without calling WriteHeader, the HTTP spec
//     requires a 200 response, so the default of 200 is correct.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code then delegates to the real writer.
func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker by delegating to the underlying ResponseWriter.
// Without this, the type assertion w.(http.Hijacker) in handleTunneling fails
// because interface embedding does not promote methods of the concrete type.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}

// handleBan is an http.Handler wrapper that feeds the ban tracker with
// per-request event data. It sits between the TLS listener and the application
// handlers (handleTunneling / handleHTTP).
//
// Note: banned IPs are already rejected at the TCP level by banListener.Accept
// before the TLS handshake, so no per-request ban check is needed here.
//
// On each request it:
//  1. Delegates to the inner handler via a statusRecorder.
//  2. Logs the completed request with method, host, path, source IP and
//     HTTP status code to syslog.
//  3. Records an eventRequest so the request-rate counter can fire.
func handleBan(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// Malformed RemoteAddr — pass through without recording.
			logger.Printf("Split failed IP %s, err=%s\"", r.RemoteAddr, err)
			//next.ServeHTTP(w, r)
			return
		}
		//handle already connected http sessions
		if isBanned(ip) {
			logger.Printf("%s == BANNED == request=%s %s%s", ip, r.Method, r.Host, r.RequestURI)
			// Hijack the raw TCP connection and close it immediately.
			// This drops the connection at the network level with no response body.
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
			// Fallback: send a minimal HTTP response if hijacking is unavailable.
			http.Error(w, "", http.StatusTooManyRequests)
			return
		}

		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		logger.Printf("%s status=%d request=%s %s%s", ip, rec.statusCode, r.Method, r.Host, r.RequestURI)

		// Pass the response status code so recordEvent can filter out 200s.
		recordEvent(ip, eventRequest, r, rec.statusCode)
	})
}

// isBanned returns true if ip has an active ban. Safe to call from any goroutine.
func isBanned(ip string) bool {
	v, ok := banTracker.Load(ip)
	if !ok {
		return false
	}
	s := v.(*ipState)
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.bannedUntil)
}

// ban sets the ban expiry on s and logs the reason. s.mu must be held by the caller.
func ban(s *ipState, ip, reason string, r *http.Request, cfg SecurityConfig) {
	s.bannedUntil = time.Now().Add(time.Duration(cfg.BanDurationSeconds) * time.Second)
	if r != nil {
		logger.Printf("%s == BAN == reason=%s duration=%ds request=%s %s%s",
			ip, reason, cfg.BanDurationSeconds, r.Method, r.Host, r.RequestURI)
	} else {
		logger.Printf("%s == BAN == reason=%s duration=%ds", ip, reason, cfg.BanDurationSeconds)
	}
}

// recordEvent records a single event for ip and bans it if either independent
// counter reaches its configured threshold.
//
// r is the originating HTTP request. It is nil for eventTLSError, which fires
// before any HTTP request exists.
//
// statusCode is the HTTP response status code. It is 0 for eventTLSError.
// For eventRequest, only non-200 status codes are counted toward the
// rate-limit threshold.
//
// Call sites:
//   - tlsErrorWriter.Write  → eventTLSError  (r = nil,            statusCode = 0)
//   - handleBan             → eventRequest   (r = current request, statusCode = response code)
func recordEvent(ip string, ev eventType, r *http.Request, statusCode int) {
	fullCfg := getConfig()
	cfg := fullCfg.Security
	now := time.Now()
	s := getOrCreateState(ip)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reset all counters when the window expires.
	if now.Sub(s.windowStart) > time.Duration(cfg.WindowSeconds)*time.Second {
		s.tlsErrors = 0
		s.recentRequests = nil
		s.windowStart = now
	}

	// Already banned — nothing more to do.
	if now.Before(s.bannedUntil) {
		return
	}

	switch ev {
	case eventTLSError:
		// TLS error check is optional. Skip entirely when disabled (0 or unset).
		if cfg.TLSBanThreshold <= 0 {
			return
		}
		// Each failed TLS handshake increments the TLS counter independently.
		// Real browsers never produce TLS errors; only scanners and probes do.
		s.tlsErrors++
		if s.tlsErrors >= cfg.TLSBanThreshold {
			ban(s, ip, "tls-errors", r, cfg)
		}

	case eventRequest:
		// Request-rate check is optional. Skip entirely when disabled.
		if cfg.RateLimitThreshold == 0 {
			return
		}
		// Only >400 responses count. A legitimate client browsing a site
		// will mostly receive 200s; only scanners and abusers accumulate
		// a sustained stream of error responses.

		//if statusCode == http.StatusOK || statusCode < 400 {
		if statusCode < http.StatusBadRequest { //400
			return
		}

		// Prune timestamps outside the rate-limit sub-window, then append now.
		cutoff := now.Add(-time.Duration(cfg.RateLimitWindowSeconds) * time.Second)
		filtered := s.recentRequests[:0]
		for _, t := range s.recentRequests {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		s.recentRequests = append(filtered, now)
		if len(s.recentRequests) >= cfg.RateLimitThreshold {
			ban(s, ip, "request-rate", r, cfg)
		}
	}
}

// startBanSweeper runs a background goroutine that periodically removes stale
// entries from banTracker to prevent unbounded memory growth.
//
// An entry is stale when the ban has expired AND the counting window has also
// expired — meaning the IP has been quiet long enough to start fresh.
func startBanSweeper(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cfg := getConfig().Security
		cutoff := time.Now().Add(-time.Duration(cfg.WindowSeconds) * time.Second)
		banTracker.Range(func(k, v any) bool {
			s := v.(*ipState)
			s.mu.Lock()
			stale := !time.Now().Before(s.bannedUntil) && s.windowStart.Before(cutoff)
			s.mu.Unlock()
			if stale {
				banTracker.Delete(k)
			}
			return true // continue iteration
		})
	}
}

// tlsErrorWriter is an io.Writer that sits between http.Server's ErrorLog and
// the underlying syslog writer. It inspects every log line for TLS handshake
// errors, extracts the source IP, and feeds an eventTLSError into the ban
// tracker before forwarding the original bytes to syslog unchanged.
//
// Why parse the log instead of wrapping the net.Listener?
//
// TLS handshake failures happen inside tls.NewListener before the connection
// reaches the HTTP handler, so handleBan never sees them. The stdlib does
// not expose a dedicated callback for handshake failures — the only observable
// surface is the ErrorLog line emitted at net/http/server.go:
//
//	c.server.logf("http: TLS handshake error from %s: %v", c.rwc.RemoteAddr(), reason)
//
// This format has been stable since Go 1.0. Any line that does not match is
// forwarded untouched, so no log output is ever lost.
type tlsErrorWriter struct {
	underlying io.Writer // the syslog writer owned by the global logger
}

// Write intercepts ErrorLog writes from http.Server. Lines containing
// "TLS handshake error from " are parsed to extract the source IP which is
// then recorded as an eventTLSError. All bytes are always forwarded to the
// underlying syslog writer regardless of whether parsing succeeds.
func (w *tlsErrorWriter) Write(p []byte) (int, error) {
	s := string(p)
	if strings.Contains(s, "TLS handshake error from ") {
		// The line format is:
		//   "http: TLS handshake error from <ip>:<port>: <reason>\n"
		// We locate "from ", read up to the next ": " to get "ip:port",
		// then split off the port with net.SplitHostPort.
		const marker = "from "
		if idx := strings.Index(s, marker); idx != -1 {
			rest := s[idx+len(marker):]
			if end := strings.Index(rest, ": "); end != -1 {
				if ip, _, err := net.SplitHostPort(rest[:end]); err == nil {
					recordEvent(ip, eventTLSError, nil, 0)
				}
			}
		}
	}
	return w.underlying.Write(p)
}

func main() {
	flag.StringVar(&configPath, "config", "config.yaml", "path to configuration file")
	flag.Parse()

	// Load and validate configuration. Fatal on error — no point starting without config.
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	setConfig(*cfg)

	// Initialize syslog. Must happen before any other component that logs.
	currentCfg := getConfig()
	initLogger(currentCfg.Syslog.Tag)

	// Start the ban entry sweeper. Runs for the lifetime of the process;
	// ban state is intentionally preserved across SIGHUP config reloads.
	go startBanSweeper(60 * time.Second)

	// Build the handler chain: handleBan wraps the core dispatch logic.
	// All requests — tunnels and HTTP — pass through the ban check first.
	handler := handleBan(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	}))

	// Install OS signal handlers for graceful reload and shutdown.
	setupSignalHandler(handler)

	// Start the HTTPS listener. Returns immediately; server runs in background.
	currentServer = startHTTPSServer(handler, currentCfg)

	// Park the main goroutine. All work happens in background goroutines:
	// one per request (stdlib http.Server), plus the signal handler and
	// ban sweeper goroutines started above.
	select {}
}
