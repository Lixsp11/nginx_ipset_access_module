# ngx_http_ipset_access_module

An NGINX module that uses Linux kernel [ipset](https://ipset.netfilter.org/) sets for IP-based access control (blacklist / whitelist).

Changes to ipset membership take effect immediately — no NGINX reload required.

## Background

This project is built upon [ngx_http_ipset_access_module](https://github.com/mehdi-roozitalab/ngx_http_ipset_access_module) by Mohammad Mahdi Roozitalab. The original project has not been maintained for several years, so we created this fork to provide a working, up-to-date implementation for modern NGINX and ipset versions.

## Features

- **Blacklist / Whitelist modes** — block or allow IPs based on ipset membership.
- **Live updates** — ipset changes take effect immediately without reloading NGINX.
- **Configurable deny status** (`ipset_status` directive) — return `403`, `404`, `444` (silent drop), or any HTTP status code.
- **Non-root worker support** — automatically retains `CAP_NET_ADMIN` across the master→worker privilege drop via `prctl(PR_SET_KEEPCAPS)` + POSIX capabilities, so worker processes can query ipsets without running as root.
- **Fail-safe behavior** — whitelist mode is fail-closed (deny on error); blacklist mode is fail-open (allow on error).
- **CDN / reverse proxy support** (`ipset_real_ip_header` directive) — read the real client IP from headers like `X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`, etc.
- **Query result caching** (`ipset_cache_ttl` directive) — per-worker LRU cache avoids redundant kernel queries. Configurable TTL (e.g. `30s`); max 10,000 entries per worker with automatic eviction.
- **Thread-local session caching** — ipset sessions are cached per worker to minimize overhead.
- **Dynamic module support** — can be compiled as a `.so` and loaded into an existing NGINX installation without recompilation.

## Requirements

- Linux kernel with ipset support
- NGINX >= 1.22 (tested on 1.24.0)
- `libipset-dev` (or `libipset-devel`)
- `libcap-dev` (or `libcap-devel`)
- Build tools: `gcc`, `make`

### Install dependencies

Debian / Ubuntu:

```bash
apt install libipset-dev libcap-dev
```

RHEL / CentOS / Fedora:

```bash
dnf install libipset-devel libcap-devel
```

## Build

### As a dynamic module (recommended)

This lets you load the module into an existing NGINX installation without recompiling NGINX itself. You need the NGINX source tree that matches your installed version.

```bash
# Get NGINX source matching your installed version
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '[\d.]+')
wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
tar xzf nginx-${NGINX_VERSION}.tar.gz
cd nginx-${NGINX_VERSION}

# Configure with the same flags as your system NGINX, plus --with-compat
# You can find the original flags with: nginx -V
./configure --with-compat \
    --add-dynamic-module=/path/to/ngx_http_ipset_access_module

# Build only the module
make modules

# Install
cp objs/ngx_http_ipset_access_module.so /usr/lib/nginx/modules/
```

### As a static module

```bash
cd nginx-${NGINX_VERSION}
./configure --add-module=/path/to/ngx_http_ipset_access_module [other flags...]
make
make install
```

## Configuration

### Loading the dynamic module

Add to the top of `nginx.conf` (or in a file under `modules-enabled/`):

```nginx
load_module modules/ngx_http_ipset_access_module.so;
```

### Directives

#### `whitelist`

- **Syntax:** `whitelist <set1> [set2] ... | off`
- **Context:** `http`, `server`

Only allow requests from IPs that are members of the specified ipset(s). All other IPs are denied.

#### `blacklist`

- **Syntax:** `blacklist <set1> [set2] ... | off`
- **Context:** `http`, `server`

Deny requests from IPs that are members of the specified ipset(s). All other IPs are allowed.

#### `ipset_status`

- **Syntax:** `ipset_status <code>`
- **Default:** `403`
- **Context:** `http`, `server`

HTTP status code returned to denied clients. Common values:

| Code | Behavior |
|------|----------|
| `403` | Forbidden (default) |
| `404` | Not Found (stealth) |
| `444` | Close connection with no response (NGINX special) |

#### `ipset_real_ip_header`

- **Syntax:** `ipset_real_ip_header <header_name>`
- **Default:** *not set* (use connection IP)
- **Context:** `http`, `server`

Specifies an HTTP request header from which to read the real client IP address. This is essential when NGINX is behind a CDN or reverse proxy, where the connection IP is the proxy's address rather than the actual client.

For headers containing multiple IPs (like `X-Forwarded-For: client, proxy1, proxy2`), the **first** (leftmost) IP is used.

If the header is not present in a request, the module falls back to the connection IP.

Common values:

| Header | Used by |
|--------|---------|
| `X-Forwarded-For` | Most CDNs and reverse proxies |
| `X-Real-IP` | NGINX reverse proxy |
| `CF-Connecting-IP` | Cloudflare |
| `True-Client-IP` | Akamai, Cloudflare (Enterprise) |

#### `ipset_cache_ttl`

- **Syntax:** `ipset_cache_ttl <time>`
- **Default:** `0` (disabled)
- **Context:** `http`, `server`

Caches ipset query results per worker process. When enabled, repeated requests from the same IP skip the kernel ipset query and use the cached result until the TTL expires.

Trade-off: reduces CPU/kernel overhead at high QPS, but ipset changes are delayed by up to the TTL duration. The cache holds up to 10,000 entries per worker with LRU eviction.

```nginx
ipset_cache_ttl 30s;   # cache results for 30 seconds
ipset_cache_ttl 0;     # disable (default, every request queries ipset)
```

### Example

```nginx
load_module modules/ngx_http_ipset_access_module.so;

http {
    server {
        listen 80;

        # Only allow IPs in the "trusted" ipset
        whitelist trusted;
        ipset_status 444;

        # Behind Cloudflare — read real client IP from header
        ipset_real_ip_header CF-Connecting-IP;

        location / {
            root /var/www/html;
        }
    }

    server {
        listen 8080;

        # Block IPs in the "blocklist" ipset
        blacklist blocklist;

        location / {
            proxy_pass http://backend;
        }
    }
}
```

### Create and manage ipsets

```bash
# Create a set
ipset create trusted hash:ip family inet

# Add IPs
ipset add trusted 10.0.0.1
ipset add trusted 192.168.1.0/24

# Remove an IP
ipset del trusted 10.0.0.1

# List members
ipset list trusted

# Persist across reboots (Debian/Ubuntu)
ipset save > /etc/ipset.rules
# Restore on boot
ipset restore < /etc/ipset.rules
```

Changes to ipset membership are reflected immediately in NGINX without any reload or restart.

## How it works

1. At **config time**, the module validates that all referenced ipset names exist and are accessible.
2. At **startup**, the module sets `PR_SET_KEEPCAPS` in the master process and raises `CAP_NET_ADMIN` in each worker process, so unprivileged workers can query the kernel's ipset subsystem.
3. At **request time**, the access-phase handler extracts the client IPv4 address and tests it against each configured ipset via libipset. Based on the result and the configured mode (whitelist/blacklist), the request is either allowed or denied.
4. ipset sessions are cached per-thread (using `pthread_key_t`) to avoid the overhead of creating a new session for every request.

## Limitations

- **IPv4 only** — IPv6 connections are passed through without checking (unless an IPv4 address is provided via `ipset_real_ip_header`).
- **`return` directive** — NGINX's `return` directive executes in the rewrite phase (before the access phase), so it bypasses this module. Use `root`, `proxy_pass`, or other content-phase directives instead.
- **libipset v6 vs v7** — The module supports both versions. Compile with `-DWITH_LIBIPSET_V6_COMPAT` if using libipset v6.

## License

LGPL-3.0. See [LICENSE](LICENSE).
