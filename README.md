# HTTPSProxy

A flexible, high-performance HTTPS reverse proxy and tunnel server written in Go. Features dynamic routing based on hostnames and URI paths, with support for hot-reloading configuration without downtime.

## Features

- 🔒 **HTTPS/TLS Support** - Secure connections with custom certificates
- 🔄 **Reverse Proxy** - Route requests to backend services based on rules
- 🚇 **HTTP CONNECT Tunneling** - Support for CONNECT method tunneling
- 🎯 **Flexible Routing** - Route by hostname patterns or URI prefixes
- 🔥 **Hot Reload** - Reload configuration without restarting (SIGHUP)
- 📝 **Syslog Integration** - Centralized logging to syslog
- ⚡ **High Performance** - Built on Go's efficient HTTP server with automatic concurrency
- 🛡️ **Port Protection** - Prevents multiple instances from binding to the same port


## Installation

### Prerequisites

- Go 1.16 or higher
- OpenSSL (for generating certificates)

### Build from Source

```bash
git clone <repository-url>
cd httpsproxy
go build -o httpsproxy httpsproxy.go
```

## Quick Start

### 1. Generate TLS Certificates

```bash
#!/usr/bin/env bash
case `uname -s` in
    Linux*)     sslConfig=/etc/ssl/openssl.cnf;;
    Darwin*)    sslConfig=/System/Library/OpenSSL/openssl.cnf;;
esac

openssl req \
    -newkey rsa:2048 \
    -x509 \
    -nodes \
    -keyout server.key \
    -new \
    -out server.crt \
    -subj /CN=localhost \
    -reqexts SAN \
    -extensions SAN \
    -config <(cat $sslConfig \
        <(printf '[SAN]\nsubjectAltName=DNS:localhost')) \
    -sha256 \
    -days 3650
```

### 2. Configure the Proxy

Create or edit `config.yaml`:

```yaml
server:
  port: 61200
  cert_file: server.crt
  key_file: server.key

syslog:
  priority: "LOG_INFO|LOG_DAEMON"
  tag: "httpsproxy"

proxy:
  dial_timeout: 10
  tunnel_destination: "10.11.12.5:2222"

routes:
  - name: "example"
    host_contains: "example.com"
    target_scheme: "http"
    target_host: "localhost:8080"
    insecure_skip_verify: false
    set_forwarded_proto: true

default:
  denied_status: 403
  denied_message: "Access Denied"
```

### 3. Run the Proxy

```bash
./httpsproxy -config config.yaml
```

Or with custom config path:

```bash
./httpsproxy -config /path/to/config.yaml
```

## Configuration

### Server Section

```yaml
server:
  port: 61200              # HTTPS listening port
  cert_file: server.crt    # Path to TLS certificate
  key_file: server.key     # Path to TLS private key
```

### Syslog Section

```yaml
syslog:
  priority: "LOG_INFO|LOG_DAEMON"  # Syslog priority level
  tag: "httpsproxy"                # Syslog tag/identifier
```

### Proxy Section

```yaml
proxy:
  dial_timeout: 10                    # TCP connection timeout (seconds)
  tunnel_destination: "host:port"     # CONNECT tunnel destination (optional)
```

**Tunnel Destination Behavior:**
- **Fixed destination**: Set `tunnel_destination` to a specific `host:port` to route all CONNECT requests to that destination
- **Dynamic destination**: Leave `tunnel_destination` empty (`""`) or omit it to forward CONNECT requests to the client's requested destination

Example configurations:

```yaml
# Fixed tunnel - all CONNECT requests go to 10.11.12.5:2222
proxy:
  dial_timeout: 10
  tunnel_destination: "10.11.12.5:2222"

# Dynamic tunnel - CONNECT requests go to their requested destination
proxy:
  dial_timeout: 10
  tunnel_destination: ""
```

### Routes Section

Routes are evaluated in order. The first matching route handles the request.

#### Host-Based Routing

Route requests based on hostname patterns:

```yaml
routes:
  - name: "my-service"
    host_contains: "api.example.com"
    target_scheme: "http"
    target_host: "backend:8080"
    insecure_skip_verify: false
    set_forwarded_proto: true
```

#### URI Prefix Routing

Route requests based on URI path prefixes:

```yaml
routes:
  - name: "admin-panel"
    uri_prefixes:
      - "/admin"
      - "/api/admin"
    target_url: "http://admin-backend:9000"
    strip_prefix: "/admin"
    insecure_skip_verify: false
```

#### Route Options

- **name** (string): Descriptive name for the route (used in logs)
- **host_contains** (string): Match if request hostname contains this string
- **uri_prefixes** (array): Match if request URI starts with any of these prefixes
- **target_scheme** (string): Target backend scheme (`http` or `https`)
- **target_host** (string): Target backend host and port
- **target_url** (string): Full target URL (alternative to scheme+host)
- **use_original_host** (bool): Keep original Host header instead of rewriting
- **insecure_skip_verify** (bool): Skip TLS certificate verification for backend
- **set_forwarded_proto** (bool): Add `X-Forwarded-Proto: https` header
- **strip_prefix** (string): Remove this prefix from the request path

### Default Section

```yaml
default:
  denied_status: 403              # HTTP status for unmatched requests
  denied_message: "Access Denied" # Response message for unmatched requests
```

## Usage Examples

### Example 1: Simple Reverse Proxy

Route all requests to `api.example.com` to a backend service:

```yaml
routes:
  - name: "api"
    host_contains: "api.example.com"
    target_scheme: "http"
    target_host: "localhost:3000"
    set_forwarded_proto: true
```

### Example 2: Path-Based Routing

Route specific paths to different backends:

```yaml
routes:
  - name: "static-files"
    uri_prefixes:
      - "/static/"
      - "/assets/"
    target_url: "http://cdn-server:8080"
  
  - name: "api-endpoints"
    uri_prefixes:
      - "/api/"
    target_url: "http://api-server:3000"
    strip_prefix: "/api"
```

### Example 3: Multiple Environments

Route based on subdomain:

```yaml
routes:
  - name: "production"
    host_contains: "prod.example.com"
    target_scheme: "https"
    target_host: "prod-backend:443"
    insecure_skip_verify: false
  
  - name: "staging"
    host_contains: "staging.example.com"
    target_scheme: "http"
    target_host: "staging-backend:8080"
```

## Signal Handling

The proxy responds to the following signals:

- **SIGHUP**: Reload configuration and restart server
  ```bash
  kill -HUP $(pgrep httpsproxy)
  ```

- **SIGINT/SIGTERM**: Graceful shutdown
  ```bash
  kill -TERM $(pgrep httpsproxy)
  # or Ctrl+C
  ```

## Logging

All logs are sent to syslog with the configured tag. View logs using:

```bash
# macOS
log show --predicate 'process == "httpsproxy"' --last 1h

# Linux (systemd)
journalctl -t httpsproxy -f

# Linux (traditional syslog)
tail -f /var/log/syslog | grep httpsproxy
```

## Security Considerations

1. **TLS Certificates**: Use proper certificates in production (not self-signed)
2. **Port Protection**: Only one instance can bind to the configured port
3. **Backend Verification**: Set `insecure_skip_verify: false` for production backends
4. **Access Control**: Use the default deny configuration to block unwanted traffic
5. **Logging**: Monitor syslog for suspicious activity

## Troubleshooting

### Port Already in Use

If you see "failed to bind to port" error, another instance is already running:

```bash
# Find the process
lsof -i :61200

# Stop it
kill $(lsof -t -i :61200)
```

### Certificate Errors

Ensure certificate and key files exist and are readable:

```bash
ls -la server.crt server.key
```

### Configuration Reload Not Working

Check syslog for configuration errors:

```bash
journalctl -t httpsproxy -n 50
```

## Performance Tips

1. **Connection Pooling**: The proxy automatically pools backend connections
2. **Concurrent Requests**: Each request is handled in its own goroutine
3. **Route Order**: Place most frequently matched routes first
4. **Logging**: Reduce log verbosity in high-traffic scenarios

## Development

### Project Structure

```
httpsproxy/
├── httpsproxy.go      # Main application code
├── config.yaml        # Configuration file
├── server.crt         # TLS certificate
├── server.key         # TLS private key
└── README.md          # This file
```

### Dependencies

```go
gopkg.in/yaml.v3       // YAML configuration parsing
```

Install dependencies:

```bash
go mod download
```

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## Credits

Based on concepts from:
- https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c
- https://gist.github.com/wwek/41790cbef2e33b6065eaea688ea54760

## Support

For issues and questions, please [open an issue](link-to-issues) on the project repository.
