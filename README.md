# httpsproxy

A lightweight HTTPS reverse proxy and TCP tunnel server written in Go (v4.0.0). Routes incoming requests to backend services based on hostname patterns, with brute-force detection, hot-reloadable configuration, and syslog integration.

## Features

- **HTTPS/TLS termination** — accepts connections with custom certificates (HTTP/1.1 only)
- **Reverse proxy** — hostname-based routing to HTTP or HTTPS backends
- **301 redirects** — route rules can issue permanent redirects instead of proxying
- **HTTP CONNECT tunneling** — forwards CONNECT requests to a fixed or dynamic destination
- **HAProxy PROXY protocol** — inbound PROXY headers are stripped and the real client IP is used; outbound PROXY v2 headers can be sent to backends per-route
- **Brute-force / IP ban** — two independent rules: TLS handshake failures and HTTP error rate; banned IPs are dropped before TLS even starts
- **Hot reload** — send `SIGHUP` to reload config and restart the listener with zero manual downtime
- **Syslog logging** — all request and error events go to syslog

## How it works

```mermaid
sequenceDiagram
    participant Client
    participant httpsproxy
    participant Backend

    alt HTTP CONNECT (tunneling)
        Client->>httpsproxy: CONNECT host:port HTTP/1.1
        httpsproxy->>Backend: TCP dial to tunnel_destination (or requested host)
        httpsproxy-->>Client: 200 OK
        Client<<->>httpsproxy: raw TCP passthrough
        httpsproxy<<->>Backend: raw TCP passthrough
    else HTTP request — route matched, redirect_url set
        Client->>httpsproxy: GET https://old.example.com/
        httpsproxy-->>Client: 301 Moved Permanently → redirect_url
    else HTTP request — route matched, tls_termination: true
        Client->>httpsproxy: GET https://app.example.com/path
        httpsproxy->>Backend: GET http://192.168.1.10:8080/path (X-Forwarded-Proto: https)
        Backend-->>httpsproxy: 200 OK
        httpsproxy-->>Client: 200 OK
    else HTTP request — route matched, tls_termination: false (default)
        Client->>httpsproxy: GET https://passthrough.example.com/path
        httpsproxy->>Backend: GET https://passthrough.example.com/path
        Backend-->>httpsproxy: 200 OK
        httpsproxy-->>Client: 200 OK
    else HTTP request — no route matched
        Client->>httpsproxy: GET https://unknown.example.com/
        httpsproxy-->>Client: 403 Forbidden
    end
```

Routes are evaluated in order. The first matching route wins.

## Installation

### Prerequisites

- Go 1.21 or higher
- OpenSSL (for generating certificates)

### Build

```bash
git clone <repository-url>
cd httpsproxy
go build -o httpsproxy httpsproxy.go
```

## Quick start

### 1. Generate a self-signed TLS certificate

```bash
case `uname -s` in
    Linux*)  sslConfig=/etc/ssl/openssl.cnf ;;
    Darwin*) sslConfig=/System/Library/OpenSSL/openssl.cnf ;;
esac

openssl req \
    -newkey rsa:2048 -x509 -nodes \
    -keyout server.key -out server.crt \
    -subj /CN=localhost \
    -reqexts SAN -extensions SAN \
    -config <(cat $sslConfig <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
    -sha256 -days 3650
```

### 2. Write a config file

```yaml
server:
  port: 8443
  cert_file: server.crt
  key_file: server.key

syslog:
  tag: "httpsproxy"

proxy:
  dial_timeout: 10
  tunnel_destination: "10.0.0.1:22"

routes:
  - name: "app"
    host_contains: "app.example.com"
    tls_termination: true
    target_host: "192.168.1.10:8080"

default:
  denied_status: 403
  denied_message: "Forbidden"
```

### 3. Run

```bash
./httpsproxy -config config.yaml
```

## Configuration reference

### `server`

| Key | Type | Description |
|---|---|---|
| `port` | int | HTTPS listening port |
| `cert_file` | string | Path to TLS certificate |
| `key_file` | string | Path to TLS private key |

### `syslog`

| Key | Type | Description |
|---|---|---|
| `priority` | string | Syslog priority (e.g. `"LOG_INFO\|LOG_DAEMON"`) |
| `tag` | string | Syslog tag shown in log lines |

### `proxy`

| Key | Type | Description |
|---|---|---|
| `dial_timeout` | int | TCP connection timeout in seconds |
| `tunnel_destination` | string | Fixed `host:port` for CONNECT tunnels. Leave empty to forward to the client's requested destination. |

### `routes`

Routes are evaluated in order; the first match wins.

| Key | Type | Description |
|---|---|---|
| `name` | string | Label used in log output |
| `host_contains` | string | Match requests whose `Host` header contains this string |
| `redirect_url` | string | If set, respond with a 301 redirect to this URL instead of proxying |
| `tls_termination` | bool | `true` → proxy to backend over **HTTP** and set `X-Forwarded-Proto: https`. `false` (default) → proxy over **HTTPS**. |
| `target_host` | string | Backend `host:port` |
| `use_original_host` | bool | Send the original `Host` header to the backend instead of `target_host` |
| `send_proxy_protocol` | bool | `true` → prepend a HAProxy PROXY protocol v2 header to every backend connection, advertising the original client address. The backend must support PROXY protocol. |

### `default`

| Key | Type | Description |
|---|---|---|
| `denied_status` | int | HTTP status returned when no route matches |
| `denied_message` | string | Response body when no route matches |

### `security`

Controls brute-force detection and automatic IP banning. All fields are optional — safe defaults are applied when the section is omitted.

Two independent ban rules fire separately and never combine:

1. **TLS errors** — ban an IP after it causes `tls_ban_threshold` failed TLS handshakes within `tls_window_seconds`. Catches port scanners and cipher probes before they consume any HTTP resources. Set to `0` to disable.
2. **HTTP error rate** — ban an IP after it accumulates `http_ban_threshold` non-200 HTTP responses within `http_window_seconds`. Disabled by default (`http_ban_threshold: 0`).

Banned IPs are dropped at the TCP `Accept()` level — before the TLS handshake — so they consume no crypto resources.

| Key | Type | Default | Description |
|---|---|---|---|
| `ban_duration_seconds` | int | `300` | How long a banned IP stays blocked |
| `tls_window_seconds` | int | `5` | Rolling time window for the TLS error counter |
| `tls_ban_threshold` | int | `3` | Number of failed TLS handshakes within the window that triggers a ban. Set to `0` to disable. |
| `http_ban_threshold` | int | `0` (disabled) | Number of non-200 HTTP responses within the window that triggers a ban. Set to `0` to disable. |
| `http_window_seconds` | int | `10` | Sliding time window for the HTTP error rate counter |

Example:

```yaml
security:
  ban_duration_seconds: 300

  # Rule 1 — TLS errors (port scanners, cipher probes)
  tls_window_seconds: 5
  tls_ban_threshold: 3

  # Rule 2 — HTTP error rate (scanners, floods)
  http_ban_threshold: 20
  http_window_seconds: 10
```

## Route examples

### Proxy to a plain-HTTP backend (TLS termination)

```yaml
- name: "app"
  host_contains: "app.example.com"
  tls_termination: true        # proxy over HTTP, add X-Forwarded-Proto: https
  target_host: "192.168.1.10:8080"
```

### Proxy to a plain-HTTP backend with PROXY protocol

```yaml
- name: "app"
  host_contains: "app.example.com"
  tls_termination: true
  target_host: "192.168.1.10:8080"
  send_proxy_protocol: true    # backend must support HAProxy PROXY protocol
```

### Proxy to an HTTPS backend

```yaml
- name: "passthrough"
  host_contains: "secure.example.com"
  # tls_termination defaults to false — proxy over HTTPS
  use_original_host: true
```

### Permanent redirect

```yaml
- name: "old-site"
  host_contains: "old.example.com"
  redirect_url: "https://new.example.com"
```

## Signal handling

| Signal | Effect |
|---|---|
| `SIGHUP` | Reload `config.yaml` and restart the listener |
| `SIGTERM` / `SIGINT` | Graceful shutdown (5-second drain) |

```bash
# Reload config
kill -HUP $(pgrep httpsproxy)

# Shut down
kill -TERM $(pgrep httpsproxy)
```

## Logging

All events are written to syslog under the configured tag. Log lines include the source IP, HTTP status code, method, host, and URI path.

```bash
# macOS
log show --predicate 'process == "httpsproxy"' --last 1h

# Linux (journald)
journalctl -t httpsproxy -f

# Linux (traditional syslog)
tail -f /var/log/syslog | grep httpsproxy
```

## Credits

Inspired by:
- https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c
- https://gist.github.com/wwek/41790cbef2e33b6065eaea688ea54760
