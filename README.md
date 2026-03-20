# ngx_http_ipset_access

An NGINX module that uses Linux kernel [ipset](https://ipset.netfilter.org/) sets for IP-based access control (blacklist / whitelist).

Changes to ipset membership take effect immediately — no NGINX reload required.

## Background

This module is based on the original [nginx_ipset_access_module](https://github.com/mehdi-roozitalab/nginx_ipset_access_module) by Mohammad Mahdi Roozitalab. The original module had several issues that prevented it from working correctly on modern systems. This fork rewrites the module with the following fixes and enhancements:

- **Fixed whitelist logic** — the original code had the whitelist condition inverted: IPs that *were* in the whitelist got denied, while IPs *not* in the whitelist were allowed through.
- **Fixed `#include` order** — NGINX headers must come before libipset headers so that `_GNU_SOURCE` is defined, which is required for `struct in6_pktinfo` on modern glibc.
- **Fixed handler phase** — moved from `NGX_HTTP_PREACCESS_PHASE` to `NGX_HTTP_ACCESS_PHASE` so the handler runs at the correct point in the request lifecycle.
- **Added `ipset_status` directive** — configurable HTTP status code for denied requests (default `403`). Use `444` to silently drop the connection.
- **Added `CAP_NET_ADMIN` retention** — the module automatically preserves `CAP_NET_ADMIN` across the master→worker privilege drop via `prctl(PR_SET_KEEPCAPS)` + POSIX capabilities, so worker processes can query ipsets without running as root.
- **Fail-closed / fail-open** — when an ipset session cannot be created, whitelist mode denies the request (fail-closed) while blacklist mode allows it (fail-open).

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
    --add-dynamic-module=/path/to/ngx_http_ipset_access

# Build only the module
make modules

# Install
cp objs/ngx_http_ipset_access.so /usr/lib/nginx/modules/
```

### As a static module

```bash
cd nginx-${NGINX_VERSION}
./configure --add-module=/path/to/ngx_http_ipset_access [other flags...]
make
make install
```

## Configuration

### Loading the dynamic module

Add to the top of `nginx.conf` (or in a file under `modules-enabled/`):

```nginx
load_module modules/ngx_http_ipset_access.so;
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

### Example

```nginx
load_module modules/ngx_http_ipset_access.so;

http {
    server {
        listen 80;

        # Only allow IPs in the "trusted" ipset
        whitelist trusted;
        ipset_status 444;

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

- **IPv4 only** — IPv6 connections are passed through without checking.
- **`return` directive** — NGINX's `return` directive executes in the rewrite phase (before the access phase), so it bypasses this module. Use `root`, `proxy_pass`, or other content-phase directives instead.
- **libipset v6 vs v7** — The module supports both versions. Compile with `-DWITH_LIBIPSET_V6_COMPAT` if using libipset v6.

## License

LGPL-3.0. See [LICENSE](LICENSE).
