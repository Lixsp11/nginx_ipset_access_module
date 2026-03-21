/*
 * Copyright (c) 2020 Mohammad Mahdi Roozitalab <mehdiboss_qi@hotmail.com>
 * Copyright (c) 2026 Contributors
 *
 * NGINX module for ipset-based access control.
 *
 * Allows using Linux kernel ipsets as dynamic blacklists or whitelists
 * for NGINX servers.  ipset membership changes take effect immediately
 * without reloading NGINX.
 *
 * Based on the original nginx_ipset_access_module by mehdi-roozitalab.
 */

/* NGINX headers must come first — they define _GNU_SOURCE */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include <libipset/session.h>
#include <libipset/types.h>


#if __GNUC__
#   define NGX_LIKELY(x)       __builtin_expect(!!(x), 1)
#   define NGX_UNLIKELY(x)     __builtin_expect(!!(x), 0)
#else
#   define NGX_LIKELY(x)        (x)
#   define NGX_UNLIKELY(x)      (x)
#endif

#define NGX_IPSET_DEFAULT_STATUS    NGX_HTTP_FORBIDDEN
#define NGX_IPSET_MAX_IP_LEN       46  /* max IPv6 text length */


/* ------------------------------------------------------------------ */
/*  ipset query helpers                                                */
/* ------------------------------------------------------------------ */

typedef struct ipset_session  ngx_ipset_session_t;

typedef enum {
    IPS_TEST_IS_IN_SET,
    IPS_TEST_IS_NOT_IN_SET,
    IPS_TEST_INVALID_SETNAME,
    IPS_TEST_INVALID_IP,
    IPS_TEST_FAIL
} ngx_ipset_test_result_t;


static int
ngx_ipset_init_types(void)
{
    ipset_load_types();
    return 0;
}

static ngx_ipset_session_t *
ngx_ipset_session_create(void)
{
#ifdef WITH_LIBIPSET_V6_COMPAT
    return ipset_session_init(printf);
#else
    return ipset_session_init(NULL, NULL);
#endif
}

static void
ngx_ipset_session_destroy(void *session)
{
    if (NGX_UNLIKELY(session == NULL)) {
        return;
    }
    ipset_session_fini(session);
}

static ngx_ipset_test_result_t
ngx_ipset_test_membership(ngx_ipset_session_t *session,
    const char *setname, const char *ip)
{
    int                      ret;
    const struct ipset_type *type;

    ret = ipset_parse_setname(session, IPSET_SETNAME, setname);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_SETNAME;
    }

    type = ipset_type_get(session, IPSET_CMD_TEST);
    if (type == NULL) {
        return IPS_TEST_FAIL;
    }

    ret = ipset_parse_elem(session, type->last_elem_optional, ip);
    if (NGX_UNLIKELY(ret < 0)) {
        return IPS_TEST_INVALID_IP;
    }

    ret = ipset_cmd(session, IPSET_CMD_TEST, 0);
    return (ret < 0) ? IPS_TEST_IS_NOT_IN_SET : IPS_TEST_IS_IN_SET;
}


/* ------------------------------------------------------------------ */
/*  Thread-local ipset session cache                                   */
/* ------------------------------------------------------------------ */

static pthread_key_t   ngx_ipset_tls_key;
static int             ngx_ipset_tls_init_result = 0;
static pthread_once_t  ngx_ipset_tls_once = PTHREAD_ONCE_INIT;

static void
ngx_ipset_tls_initializer(void)
{
    ngx_ipset_tls_init_result = ngx_ipset_init_types();
    if (ngx_ipset_tls_init_result) {
        return;
    }

    if (pthread_key_create(&ngx_ipset_tls_key, ngx_ipset_session_destroy)) {
        ngx_ipset_tls_init_result = ngx_errno;
    }
}

static ngx_ipset_session_t *
ngx_ipset_get_session(void)
{
    ngx_ipset_session_t *session;

    pthread_once(&ngx_ipset_tls_once, ngx_ipset_tls_initializer);
    if (NGX_UNLIKELY(ngx_ipset_tls_init_result)) {
        ngx_set_errno(ngx_ipset_tls_init_result);
        return NULL;
    }

    session = pthread_getspecific(ngx_ipset_tls_key);
    if (NGX_LIKELY(session != NULL)) {
        return session;
    }

    session = ngx_ipset_session_create();
    if (NGX_UNLIKELY(session == NULL)) {
        return NULL;
    }

    pthread_setspecific(ngx_ipset_tls_key, session);
    return session;
}


/* ------------------------------------------------------------------ */
/*  Module configuration                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    enum {
        e_mode_not_configured = 0,
        e_mode_off,
        e_mode_blacklist,
        e_mode_whitelist
    }             mode;
    ngx_array_t   sets;             /* array of ngx_str_t (ipset names)   */
    ngx_int_t     deny_status;      /* HTTP status to return when denying */
    ngx_str_t     real_ip_header;   /* header name for real client IP     */
} ngx_ipset_access_srv_conf_t;


static int
ngx_ipset_str_copy(ngx_pool_t *pool, ngx_str_t *dst, const ngx_str_t *src)
{
    if (NGX_UNLIKELY(dst->len >= src->len)) {
        ngx_memcpy(dst->data, src->data, src->len);
        dst->len = src->len;
        return 0;
    }

    if (NGX_UNLIKELY(dst->data != NULL)) {
        ngx_pfree(pool, dst->data);
    }

    dst->data = ngx_pcalloc(pool, src->len + 1);
    if (dst->data == NULL) {
        dst->len = 0;
        return ENOMEM;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return 0;
}

static int
ngx_ipset_str_array_copy(ngx_pool_t *pool, ngx_array_t *dst,
    const ngx_array_t *src, ngx_uint_t start)
{
    ngx_uint_t        i;
    ngx_str_t        *d;
    const ngx_str_t  *s;

    d = ngx_array_push_n(dst, src->nelts - start);
    if (d == NULL) {
        return ENOMEM;
    }

    s = ((const ngx_str_t *) src->elts) + start;
    for (i = start; i < src->nelts; i++) {
        if (ngx_ipset_str_copy(pool, d++, s++) != 0) {
            return ENOMEM;
        }
    }
    return 0;
}


static void *
ngx_ipset_access_create_srv_conf(ngx_conf_t *cf)
{
    ngx_ipset_access_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ipset_access_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->deny_status = NGX_CONF_UNSET;

    if (ngx_array_init(&conf->sets, cf->pool, 0, sizeof(ngx_str_t))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "ipset_access: failed to allocate sets array");
        return NULL;
    }

    return conf;
}

static char *
ngx_ipset_access_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ipset_access_srv_conf_t *prev = parent;
    ngx_ipset_access_srv_conf_t *conf = child;

    if (conf->mode == e_mode_not_configured) {
        conf->mode = prev->mode;
        if (prev->sets.nelts) {
            if (ngx_ipset_str_array_copy(cf->pool, &conf->sets,
                                         &prev->sets, 0) != 0)
            {
                return (char *) NGX_ERROR;
            }
        }
    }

    ngx_conf_merge_value(conf->deny_status, prev->deny_status,
                         NGX_IPSET_DEFAULT_STATUS);

    ngx_conf_merge_str_value(conf->real_ip_header, prev->real_ip_header, "");

    return NGX_OK;
}

static char *
ngx_ipset_access_parse_list(ngx_conf_t *cf, ngx_command_t *command,
    void *pv_conf)
{
    ngx_uint_t                   i;
    ngx_str_t                   *value;
    ngx_ipset_session_t         *session;
    ngx_str_t                   *args = cf->args->elts;
    ngx_ipset_access_srv_conf_t *conf = pv_conf;

    /* "blacklist off" or "whitelist off" disables the module */
    if (args[1].len == 3 && ngx_memcmp(args[1].data, "off", 3) == 0) {
        conf->mode = e_mode_off;
        return NGX_OK;
    }

    if (ngx_ipset_str_array_copy(cf->pool, &conf->sets, cf->args, 1) != 0) {
        return (char *) NGX_ERROR;
    }

    conf->mode = (args[0].data[0] == 'b') ? e_mode_blacklist
                                           : e_mode_whitelist;

    /* validate that the named ipsets exist */
    value = conf->sets.elts;
    session = ngx_ipset_get_session();
    if (session == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "ipset_access: cannot create ipset session "
                      "(check CAP_NET_ADMIN or run as root)");
        return (char *) NGX_ERROR;
    }

    for (i = 0; i < conf->sets.nelts; i++, value++) {
        ngx_ipset_test_result_t result;

        result = ngx_ipset_test_membership(session,
                                           (const char *) value->data,
                                           "127.0.0.1");
        if (result == IPS_TEST_FAIL || result == IPS_TEST_INVALID_SETNAME) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                          "ipset_access: set \"%V\" does not exist "
                          "or is inaccessible", value);
            return (char *) NGX_ERROR;
        }
    }

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/*  Forward declaration                                                */
/* ------------------------------------------------------------------ */

static ngx_int_t ngx_ipset_access_handler(ngx_http_request_t *r);


/* ------------------------------------------------------------------ */
/*  NGINX module registration                                          */
/* ------------------------------------------------------------------ */

#define IPSET_ACCESS_COMMAND(name)                                           \
    { ngx_string(name),                                                      \
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,                  \
      ngx_ipset_access_parse_list,                                           \
      NGX_HTTP_SRV_CONF_OFFSET,                                              \
      0,                                                                     \
      NULL }

static ngx_command_t ngx_ipset_access_commands[] = {

    IPSET_ACCESS_COMMAND("blacklist"),
    IPSET_ACCESS_COMMAND("whitelist"),

    { ngx_string("ipset_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipset_access_srv_conf_t, deny_status),
      NULL },

    { ngx_string("ipset_real_ip_header"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_ipset_access_srv_conf_t, real_ip_header),
      NULL },

    ngx_null_command
};

static ngx_int_t
ngx_ipset_access_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_ipset_access_handler;

    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/*  CAP_NET_ADMIN handling for non-root workers                        */
/*                                                                     */
/*  init_module: runs in the master (root) before forking workers.     */
/*  Sets PR_SET_KEEPCAPS so permitted capabilities survive the         */
/*  upcoming setuid() to the unprivileged worker user.                 */
/*                                                                     */
/*  init_process: runs in each worker after fork + setuid.  The        */
/*  effective capability set is empty at this point, but the           */
/*  permitted set still contains CAP_NET_ADMIN thanks to keepcaps.    */
/*  We raise it back into the effective set so libipset's netlink      */
/*  operations succeed.                                                */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_ipset_access_init_module(ngx_cycle_t *cycle)
{
    if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "ipset_access: prctl(PR_SET_KEEPCAPS) failed");
    }
    return NGX_OK;
}

static ngx_int_t
ngx_ipset_access_init_process(ngx_cycle_t *cycle)
{
    cap_t       caps;
    cap_value_t net_admin = CAP_NET_ADMIN;

    caps = cap_get_proc();
    if (caps == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "ipset_access: cap_get_proc() failed");
        return NGX_OK;
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &net_admin, CAP_SET) == -1
        || cap_set_flag(caps, CAP_PERMITTED, 1, &net_admin, CAP_SET) == -1)
    {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "ipset_access: cap_set_flag() failed");
        cap_free(caps);
        return NGX_OK;
    }

    if (cap_set_proc(caps) == -1) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                      "ipset_access: cap_set_proc() failed, "
                      "worker may lack CAP_NET_ADMIN");
    }

    cap_free(caps);
    return NGX_OK;
}


static ngx_http_module_t ngx_ipset_access_module_ctx = {
    NULL,                                    /* preconfiguration */
    ngx_ipset_access_postconfiguration,      /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* merge main configuration */

    ngx_ipset_access_create_srv_conf,        /* create server configuration */
    ngx_ipset_access_merge_srv_conf,         /* merge server configuration */

    NULL,                                    /* create location configuration */
    NULL                                     /* merge location configuration */
};

ngx_module_t ngx_http_ipset_access_module = {
    NGX_MODULE_V1,
    &ngx_ipset_access_module_ctx,            /* module context */
    ngx_ipset_access_commands,               /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    ngx_ipset_access_init_module,            /* init module */
    ngx_ipset_access_init_process,           /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ------------------------------------------------------------------ */
/*  Real IP extraction from request headers                            */
/* ------------------------------------------------------------------ */

/*
 * Extract the client IP string to use for ipset testing.
 *
 * If ipset_real_ip_header is configured, look up that header in the
 * request.  For X-Forwarded-For style headers (comma-separated list),
 * the first (leftmost) IP is used — this is the original client IP
 * appended by the first proxy in the chain.
 *
 * Returns a null-terminated IP string in the provided buffer,
 * or NULL on failure.
 */
static char *
ngx_ipset_extract_ip(ngx_http_request_t *r,
    ngx_ipset_access_srv_conf_t *conf, char *buf, size_t buflen)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t        i;
    u_char           *p, *end;
    size_t            len;

    /* if no header configured, fall back to connection IP */
    if (conf->real_ip_header.len == 0) {
        goto use_sockaddr;
    }

    /* search request headers for the configured header name */
    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len != conf->real_ip_header.len) {
            continue;
        }

        if (ngx_strncasecmp(header[i].key.data, conf->real_ip_header.data,
                            conf->real_ip_header.len) != 0)
        {
            continue;
        }

        /* found the header — extract the first IP from its value */
        p = header[i].value.data;
        end = p + header[i].value.len;

        /* skip leading whitespace */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /* find the end of the first IP (delimited by comma or whitespace) */
        len = 0;
        while (p + len < end
               && p[len] != ','
               && p[len] != ' '
               && p[len] != '\t')
        {
            len++;
        }

        if (len == 0 || len >= buflen) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "ipset_access: invalid IP in header \"%V\"",
                          &conf->real_ip_header);
            goto use_sockaddr;
        }

        ngx_memcpy(buf, p, len);
        buf[len] = '\0';
        return buf;
    }

    /* header not found, fall back */
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ipset_access: header \"%V\" not found, using connection IP",
                   &conf->real_ip_header);

use_sockaddr:

    if (r->connection->sockaddr->sa_family != AF_INET) {
        return NULL;
    }

    return inet_ntoa(((struct sockaddr_in *) r->connection->sockaddr)->sin_addr);
}


/* ------------------------------------------------------------------ */
/*  Access-phase handler                                               */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_ipset_access_handler(ngx_http_request_t *r)
{
    ngx_ipset_access_srv_conf_t  *conf;
    ngx_ipset_session_t          *session;
    ngx_ipset_test_result_t       result;
    ngx_uint_t                    i;
    ngx_str_t                    *set;
    char                         *ip;
    char                          ip_buf[NGX_IPSET_MAX_IP_LEN + 1];

    conf = ngx_http_get_module_srv_conf(r, ngx_http_ipset_access_module);

    /* skip if not configured or explicitly disabled */
    if (conf->mode != e_mode_whitelist && conf->mode != e_mode_blacklist) {
        return NGX_DECLINED;
    }

    ip = ngx_ipset_extract_ip(r, conf, ip_buf, sizeof(ip_buf));
    if (ip == NULL) {
        /* non-IPv4 connection with no header override — skip */
        return NGX_DECLINED;
    }

    session = ngx_ipset_get_session();
    if (session == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ipset_access: cannot create session for \"%s\"", ip);

        /* fail-closed for whitelist, fail-open for blacklist */
        if (conf->mode == e_mode_whitelist) {
            return conf->deny_status;
        }
        return NGX_OK;
    }

    result = IPS_TEST_IS_NOT_IN_SET;
    set = conf->sets.elts;

    for (i = 0; i < conf->sets.nelts; i++, set++) {
        result = ngx_ipset_test_membership(session,
                                           (const char *) set->data, ip);
        if (result == IPS_TEST_IS_IN_SET) {
            break;
        }

        if (result == IPS_TEST_FAIL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ipset_access: error testing \"%s\" in set \"%V\"",
                          ip, set);
            break;
        }
    }

    /*
     * Whitelist: deny if the IP is NOT in any configured set.
     * Blacklist: deny if the IP IS in any configured set.
     */
    if ((conf->mode == e_mode_whitelist && result != IPS_TEST_IS_IN_SET)
        || (conf->mode == e_mode_blacklist && result == IPS_TEST_IS_IN_SET))
    {
        r->keepalive = 0;

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "ipset_access: denied \"%s\" (%s, status=%d)",
                      ip,
                      (conf->mode == e_mode_whitelist) ? "whitelist"
                                                       : "blacklist",
                      conf->deny_status);

        return conf->deny_status;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ipset_access: allowed \"%s\"", ip);

    return NGX_OK;
}
