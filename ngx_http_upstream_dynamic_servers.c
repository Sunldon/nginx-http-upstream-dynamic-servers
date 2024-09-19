#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_resolver_t      *resolver;
    ngx_msec_t           resolver_timeout;
    ngx_array_t          dynamic_servers;
    ngx_http_conf_ctx_t *conf_ctx;
    ngx_rbtree_t         rbtree;
    ngx_rbtree_node_t    sentinel;
} ngx_http_upstream_dynamic_server_main_conf_t;

typedef struct {
    ngx_queue_t                 queue;
    ngx_pool_t                 *pool;
    ngx_uint_t                  refer_num;
    ngx_http_upstream_server_t *server;
} ngx_http_upstream_dynamic_server_pool_node_t;

typedef struct {
    ngx_http_upstream_init_peer_pt                original_init_peer;
    ngx_http_upstream_dynamic_server_pool_node_t *us_node;
} ngx_http_upstream_dynamic_server_srv_conf_t;

typedef struct {
    ngx_queue_t                                   pool_queue;
    ngx_uint_t                                    pool_queue_len;
    ngx_int_t                                     resolve_num;
    ngx_http_upstream_server_t                   *server;
    ngx_http_upstream_srv_conf_t                 *upstream_conf;
    ngx_str_t                                     host;
    in_port_t                                     port;
    ngx_event_t                                   timer;
    ngx_int_t                                     use_last;
} ngx_http_upstream_dynamic_server_conf_t;

typedef struct {
    void                  *data;
    ngx_event_get_peer_pt  original_get_peer;
    ngx_event_free_peer_pt original_free_peer;
#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt  original_set_session;
    ngx_event_save_peer_session_pt original_save_session;
#endif
} ngx_http_upstream_dynamic_peer_data_t;

static ngx_str_t ngx_http_upstream_dynamic_server_null_route =
    ngx_string("127.255.255.255");

static void *ngx_http_upstream_dynamic_server_main_conf(ngx_conf_t *cf);
static void *ngx_http_upstream_dynamic_create_srv_conf(ngx_conf_t *cf);
static void  ngx_http_upstream_dynamic_servers_exit_process(ngx_cycle_t *cycle);
static void  ngx_http_upstream_dynamic_server(ngx_event_t *ev);
static void  ngx_http_upstream_dynamic_server_handler(ngx_resolver_ctx_t *ctx);

ngx_int_t ngx_http_upstream_dynamic_directive(
    ngx_conf_t *cf, ngx_http_upstream_server_t *us, ngx_uint_t *i);
static char *ngx_http_upstream_dynamic_servers_merge_conf(
    ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_upstream_free_dynamic_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static ngx_int_t ngx_http_upstream_dynamic_servers_init_process(
    ngx_cycle_t *cycle);
static ngx_int_t ngx_http_upstream_init_dynamic_server_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_dynamic_server_peer(
    ngx_peer_connection_t *pc, void *data);
static ngx_rbtree_node_t *ngx_http_upstream_dynamic_server_rbtree_lookup(
    ngx_rbtree_t *rbtree, uint32_t hash, ngx_str_t *key);
static void ngx_http_upstream_dynamic_rbtree_server_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_dynamic_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_dynamic_save_session(
    ngx_peer_connection_t *pc, void *data);
#endif

static ngx_http_module_t ngx_http_upstream_dynamic_servers_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    ngx_http_upstream_dynamic_server_main_conf, /* create main configuration*/
    NULL,                                       /* init main configuration*/
    ngx_http_upstream_dynamic_create_srv_conf,  /* create server configuration*/
    ngx_http_upstream_dynamic_servers_merge_conf, /*merge server configuration*/
    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_upstream_dynamic_servers_module = {NGX_MODULE_V1,
    &ngx_http_upstream_dynamic_servers_module_ctx,  /* module context */
    NULL,                                           /* module directives */
    NGX_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    ngx_http_upstream_dynamic_servers_init_process, /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    ngx_http_upstream_dynamic_servers_exit_process, /* exit process */
    NULL,                                           /* exit master */
    NGX_MODULE_V1_PADDING};

static void
ngx_http_upstream_dynamic_servers_clean_up(void *data)
{
    ngx_http_upstream_dynamic_server_pool_node_t *node = data;
    ngx_uint_t refer_num = node->refer_num;
    node->refer_num = refer_num > 0 ? refer_num-- : 0;
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
        "clean host %s pool_node:%p ref:%d", node->server->host.data, node,
        node->refer_num);
}

static ngx_int_t
ngx_http_upstream_init_dynamic_server_peer(
    ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_dynamic_peer_data_t       *drp;
    ngx_http_upstream_dynamic_server_srv_conf_t *udscf;
    ngx_pool_cleanup_t                          *cleanup;

    udscf = ngx_http_conf_upstream_srv_conf(
        us, ngx_http_upstream_dynamic_servers_module);
    udscf->us_node->refer_num++;
    ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
        "init peer %p host:'%V' refer_num:%d", udscf->us_node, &udscf->us_node->server->host, udscf->us_node->refer_num);        
    if (udscf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    drp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_dynamic_peer_data_t));
    if (drp == NULL) {
        return NGX_ERROR;
    }

    cleanup = ngx_pool_cleanup_add(r->pool, 0);
    cleanup->data = udscf->us_node;
    cleanup->handler = ngx_http_upstream_dynamic_servers_clean_up;

    drp->data = r->upstream->peer.data;
    drp->original_get_peer = r->upstream->peer.get;
    r->upstream->peer.get = ngx_http_upstream_get_dynamic_server_peer;
    drp->original_free_peer = r->upstream->peer.free;
    r->upstream->peer.free = ngx_http_upstream_free_dynamic_peer;
#if (NGX_HTTP_SSL)
    drp->original_set_session = r->upstream->peer.set_session;
    drp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_dynamic_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_dynamic_save_session;
#endif
    r->upstream->peer.data = drp;
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_get_dynamic_server_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                                      res;
    uint32_t                                       hash;
    ngx_rbtree_node_t                             *node;
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    ngx_http_upstream_dynamic_server_pool_node_t **rbtree_node, *pool_node;
    ngx_http_upstream_dynamic_peer_data_t         *drp;

    drp = data;
    res = drp->original_get_peer(pc, drp->data);
    if (res == NGX_OK) {
        hash = ngx_crc32_short(pc->host->data, pc->host->len);
        udsmcf = ngx_http_cycle_get_module_main_conf(
            ngx_cycle, ngx_http_upstream_dynamic_servers_module);
        node = ngx_http_upstream_dynamic_server_rbtree_lookup(
            &udsmcf->rbtree, hash, pc->host);
        if (NULL != node) {
            node->key = hash;
            rbtree_node =
                (ngx_http_upstream_dynamic_server_pool_node_t **) &node->color;
            pool_node = *rbtree_node;
            pool_node->refer_num++;
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "get peer %p host:'%V' refer_num:%d ", pool_node, pc->host, pool_node->refer_num);            
        } else {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                "get peer couldn't find '%V' node", &pc->host);
        }
    }
    return res;
}

static void
ngx_http_upstream_free_dynamic_peer(
    ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{
    uint32_t                                       hash;
    ngx_rbtree_node_t                             *node;
    ngx_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    ngx_http_upstream_dynamic_server_pool_node_t **rbtree_node, *pool_node;
    ngx_http_upstream_dynamic_peer_data_t         *drp;

    drp = data;
    udsmcf = ngx_http_cycle_get_module_main_conf(
        ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    hash = ngx_crc32_short(pc->host->data, pc->host->len);
    node = ngx_http_upstream_dynamic_server_rbtree_lookup(
        &udsmcf->rbtree, hash, pc->host);
    if (NULL != node) {
        node->key = hash;
        rbtree_node =
            (ngx_http_upstream_dynamic_server_pool_node_t **) &node->color;
        pool_node = (*rbtree_node);
        if (NULL != pool_node) {
            ngx_uint_t refer_num = pool_node->refer_num;
            pool_node->refer_num = refer_num > 0 ? refer_num-- : 0;
            ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                "free %p %s refer_num:%d", pool_node, pc->host->data,
                pool_node->refer_num);
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "free peer couldn't '%V' node", &pc->host);
    }

    drp->original_free_peer(pc, drp->data, state);
}

#if (NGX_HTTP_SSL)
static ngx_int_t
ngx_http_upstream_dynamic_set_session(ngx_peer_connection_t *pc, void *data)
{
    return NGX_OK;
}
static void
ngx_http_upstream_dynamic_save_session(ngx_peer_connection_t *pc, void *data)
{
    return;
}
#endif

ngx_int_t
ngx_http_upstream_dynamic_directive(
    ngx_conf_t *cf, ngx_http_upstream_server_t *us, ngx_uint_t *i)
{
    size_t                                        size;
    ngx_url_t                                     u;
    uint32_t                                      hash;
    ngx_str_t                                    *value;
    ngx_rbtree_node_t                            *node;
    ngx_http_upstream_srv_conf_t                 *uscf;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;
    ngx_http_upstream_dynamic_server_conf_t      *dynamic_server;

    dynamic_server = NULL;
    value = cf->args->elts;
    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    udsmcf = ngx_http_conf_get_module_main_conf(
        cf, ngx_http_upstream_dynamic_servers_module);

    if (ngx_strncmp(value[(*i)].data, "resolve", 7) != 0) {
        return NGX_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    us->host = u.url;

    /* replace value[1] to static to prevent nginx take too long time to resolve
     * it using function ngx_parse_url in function ngx_http_upstream_server it
     * doesn't matter if a server will be dynamic resolved
     */
    value[1] = ngx_http_upstream_dynamic_server_null_route;
    u.default_port = 80;
    u.no_resolve = 1;
    ngx_parse_url(cf->pool, &u);
    if (!u.addrs || !u.addrs[0].sockaddr) {
        dynamic_server = ngx_array_push(&udsmcf->dynamic_servers);
        if (dynamic_server == NULL) {
            return NGX_ERROR;
        }
        ngx_memzero(
            dynamic_server, sizeof(ngx_http_upstream_dynamic_server_conf_t));
        us->down = 1;
        dynamic_server->server = us;
        dynamic_server->upstream_conf = uscf;
        dynamic_server->host = u.host;
        dynamic_server->port =
            (in_port_t) (u.no_port ? u.default_port : u.port);

        hash = ngx_crc32_short(dynamic_server->server->host.data,
            dynamic_server->server->host.len);
        node = ngx_http_upstream_dynamic_server_rbtree_lookup(
            &udsmcf->rbtree, hash, &dynamic_server->server->host);
        if (NULL == node) {
            size = offsetof(ngx_rbtree_node_t, color) +
                   sizeof(ngx_http_upstream_dynamic_server_pool_node_t *);
            node = ngx_pcalloc(cf->pool, size);
            if (node == NULL) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "new node fail");
                return NGX_ERROR;
            }
            node->key = hash;
            ngx_rbtree_insert(&udsmcf->rbtree, node);
        } else {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "The server '%V' should not be used more than once in all "
                "upstream block",
                &dynamic_server->server->host);
            return NGX_ERROR;
        }
    }

    if (*i == cf->args->nelts - 1 ||
        ngx_strncmp(value[(*i) + 1].data, "use_last", 8) != 0 ||
        !dynamic_server) {
        return NGX_AGAIN;
    }

    (*i)++;
    dynamic_server->use_last = 1;
    return NGX_AGAIN;
}

static void *
ngx_http_upstream_dynamic_server_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;

    udsmcf = ngx_pcalloc(
        cf->pool, sizeof(ngx_http_upstream_dynamic_server_main_conf_t));
    if (udsmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&udsmcf->dynamic_servers, cf->pool, 1,
            sizeof(ngx_http_upstream_dynamic_server_conf_t)) != NGX_OK) {
        return NULL;
    }

    udsmcf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    ngx_rbtree_init(&udsmcf->rbtree, &udsmcf->sentinel,
        ngx_http_upstream_dynamic_rbtree_server_insert_value);
    return udsmcf;
}

static char *
ngx_http_upstream_dynamic_servers_merge_conf(
    ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_core_loc_conf_t                     *core_loc_conf;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;

    udsmcf = ngx_http_conf_get_module_main_conf(
        cf, ngx_http_upstream_dynamic_servers_module);
    if (udsmcf->dynamic_servers.nelts > 0) {
        core_loc_conf =
            ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
#if nginx_version >= 1009011
        if (core_loc_conf->resolver == NULL ||
            core_loc_conf->resolver->connections.nelts == 0) {
#else
        if (core_loc_conf->resolver == NULL ||
            core_loc_conf->resolver->udp_connections.nelts == 0) {
#endif
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "resolver must be defined at the 'http' level of the config");
            return NGX_CONF_ERROR;
        }
        udsmcf->conf_ctx = cf->ctx;
        udsmcf->resolver = core_loc_conf->resolver;
        ngx_conf_merge_msec_value(
            udsmcf->resolver_timeout, core_loc_conf->resolver_timeout, 30000);
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_upstream_dynamic_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_dynamic_server_srv_conf_t *udscf;

    udscf = ngx_pcalloc(
        cf->pool, sizeof(ngx_http_upstream_dynamic_server_srv_conf_t));
    if (udscf == NULL) {
        return NULL;
    }
    return udscf;
}

static ngx_int_t
ngx_http_upstream_dynamic_servers_init_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                                    i;
    ngx_event_t                                  *timer;
    ngx_http_upstream_dynamic_server_srv_conf_t  *udscf;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;
    ngx_http_upstream_dynamic_server_conf_t      *dynamic_server;

    udsmcf = ngx_http_cycle_get_module_main_conf(
        cycle, ngx_http_upstream_dynamic_servers_module);
    dynamic_server = udsmcf->dynamic_servers.elts;

    for (i = 0; i < udsmcf->dynamic_servers.nelts; i++) {
        ngx_queue_init(&dynamic_server[i].pool_queue);
        timer = &dynamic_server[i].timer;
        timer->handler = ngx_http_upstream_dynamic_server;
        timer->log = cycle->log;
        timer->data = &dynamic_server[i];
        udscf = ngx_http_conf_upstream_srv_conf(dynamic_server[i].upstream_conf,
            ngx_http_upstream_dynamic_servers_module);
        udscf->original_init_peer = dynamic_server[i].upstream_conf->peer.init;
        ngx_http_upstream_dynamic_server(timer);
    }

    return NGX_OK;
}

static void
ngx_http_upstream_dynamic_server(ngx_event_t *ev)
{
    ngx_uint_t                                    refresh_in;
    ngx_resolver_ctx_t                           *ctx;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;
    ngx_http_upstream_dynamic_server_conf_t      *dynamic_server;

    refresh_in = 1000;
    dynamic_server = ev->data;
    udsmcf = ngx_http_cycle_get_module_main_conf(
        ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    ctx = ngx_resolve_start(udsmcf->resolver, NULL);

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
            "upstream-dynamic-servers: resolver start error for '%V'",
            &dynamic_server->host);
        return;
    }
    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
            "upstream-dynamic-servers: no resolver defined to resolve '%V'",
            &dynamic_server->host);
        return;
    }

    ctx->name = dynamic_server->host;
    ctx->handler = ngx_http_upstream_dynamic_server_handler;
    ctx->data = dynamic_server;
    ctx->timeout = udsmcf->resolver_timeout;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ev->log, 0,
        "upstream-dynamic-servers: Resolving '%V'", &ctx->name);
    if (ngx_resolve_name(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
            "upstream-dynamic-servers: ngx_resolve_name failed for '%V'",
            &ctx->name);
        if (dynamic_server->resolve_num == 0) {
            dynamic_server->resolve_num = 1;
            refresh_in = ngx_random() % 5000;
        }
        ngx_add_timer(&dynamic_server->timer, refresh_in);
    }
}

static void
ngx_http_upstream_dynamic_server_handler(ngx_resolver_ctx_t *ctx)
{
    size_t             len;
    u_char            *text;
    ngx_url_t          u;
    ngx_conf_t         cf;
    uint32_t           hash;
    socklen_t          socklen;
    ngx_rbtree_node_t *node;
    struct sockaddr   *sockaddr;
    ngx_addr_t        *addr, *addrs, *existing_addr;
    ngx_pool_t        *new_pool, *parse_pool;
    ngx_queue_t       *p, *n, *pool_queue;
    ngx_uint_t         i, j, founded, index, refresh_in;
    ngx_http_upstream_dynamic_server_srv_conf_t  *udscf;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;
    ngx_http_upstream_dynamic_server_conf_t      *dynamic_server;
    ngx_http_upstream_dynamic_server_pool_node_t *pool_node, *tmp_node,
        **rbtree_node;

    index = 0;
    refresh_in = 1000;
    parse_pool = NULL;
    dynamic_server = ctx->data;
    udsmcf = ngx_http_cycle_get_module_main_conf(
        ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
        "upstream-dynamic-servers: Finished resolving '%V'", &ctx->name);

    if (dynamic_server->use_last && ctx->state == NGX_RESOLVE_TIMEDOUT) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: '%V' resolve timeout and use last ip",
            &ctx->name);
        goto end;
    }

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: '%V' could not be resolved (%i: %s)",
            &ctx->name, ctx->state, ngx_resolver_strerror(ctx->state));

        ngx_memzero(&u, sizeof(ngx_url_t));
        // If the domain fails to resolve on start up, assign a static IP that
        // should never route (we'll also mark it as down in the upstream later
        // on). This is to account for various things inside nginx that seem to
        // expect a server to always have at least 1 IP.
        u.url = ngx_http_upstream_dynamic_server_null_route;
        u.default_port = 80;
        u.no_resolve = 1;
        parse_pool = ngx_create_pool(1024, ctx->resolver->log);
        if (parse_pool == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                "upstream-dynamic-servers: Could not create parse_pool");
            goto end;
        } else {
            if (ngx_parse_url(parse_pool, &u) != NGX_OK) {
                if (u.err) {
                    ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                        "%s in upstream \"%V\"", u.err, &u.url);
                }

                goto end;
            }
        }
        ctx->addr.sockaddr = u.addrs[0].sockaddr;
        ctx->addr.socklen = u.addrs[0].socklen;
        ctx->addr.name = u.addrs[0].name;
        ctx->addrs = &ctx->addr;
        ctx->naddrs = u.naddrs;
    }

    if (ctx->naddrs != dynamic_server->server->naddrs) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: reinit_upstream '%V' because ip's "
            "number change",
            &ctx->name);
        goto reinit_upstream;
    }

    for (i = 0; i < ctx->naddrs; i++) {
        founded = 0;
        for (j = 0; j < ctx->naddrs; j++) {
            existing_addr = &dynamic_server->server->addrs[j];
            if (ngx_cmp_sockaddr(existing_addr->sockaddr,
                    existing_addr->socklen, ctx->addrs[i].sockaddr,
                    ctx->addrs[i].socklen, 0) == NGX_OK) {
                founded = 1;
                break;
            }
        }

        if (!founded) {
            ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                "upstream-dynamic-servers: reinit_upstream '%V' because new ip",
                &ctx->name);
            goto reinit_upstream;
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
        "upstream-dynamic-servers: No DNS changes for '%V' - keeping "
        "existing upstream configuration",
        &ctx->name);
    goto end;

reinit_upstream:
    new_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ctx->resolver->log);
    if (new_pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: Could not create new pool");
        goto end;
    }

    pool_node = ngx_palloc(
        new_pool, sizeof(ngx_http_upstream_dynamic_server_pool_node_t));
    if (pool_node == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: Could not create pool_node");
        goto end;
    }
    pool_node->server = dynamic_server->server;
    ngx_log_error(NGX_LOG_DEBUG, ctx->resolver->log, 0,
        "new_pool %p host:%s ", pool_node, dynamic_server->server->host.data);
    pool_node->pool = new_pool;
    pool_node->refer_num = 0;

    hash = ngx_crc32_short(
        dynamic_server->server->host.data, dynamic_server->server->host.len);
    node = ngx_http_upstream_dynamic_server_rbtree_lookup(
        &udsmcf->rbtree, hash, &dynamic_server->server->host);
    if (NULL != node) {
        node->key = hash;
        rbtree_node =
            (ngx_http_upstream_dynamic_server_pool_node_t **) &node->color;
        *rbtree_node = pool_node;
    } else {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "reinit upstream couldn't find '%V' node",
            &dynamic_server->server->host);
    }

    udscf = ngx_http_conf_upstream_srv_conf(dynamic_server->upstream_conf,
        ngx_http_upstream_dynamic_servers_module);
    udscf->us_node = pool_node;
    ngx_log_debug(NGX_LOG_DEBUG_CORE, ctx->resolver->log, 0,
        "upstream-dynamic-servers: DNS changes for '%V' detected - "
        "reinitialize upstream configuration",
        &ctx->name);

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.name = "dynamic_server_init_upstream";
    cf.cycle = (ngx_cycle_t *) ngx_cycle;
    cf.pool = new_pool;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    cf.log = ngx_cycle->log;
    cf.ctx = udsmcf->conf_ctx;

    addrs = ngx_pcalloc(new_pool, ctx->naddrs * sizeof(ngx_addr_t));
    ngx_memcpy(addrs, ctx->addrs, ctx->naddrs * sizeof(ngx_addr_t));

    for (i = 0; i < ctx->naddrs; i++) {
        addr = &addrs[i];
        socklen = ctx->addrs[i].socklen;
        sockaddr = ngx_palloc(new_pool, socklen);
        ngx_memcpy(sockaddr, ctx->addrs[i].sockaddr, socklen);
        switch (sockaddr->sa_family) {
            case AF_INET6:
                ((struct sockaddr_in6 *) sockaddr)->sin6_port =
                    htons((u_short) dynamic_server->port);
                break;
            default:
                ((struct sockaddr_in *) sockaddr)->sin_port =
                    htons((u_short) dynamic_server->port);
        }

        addr->sockaddr = sockaddr;
        addr->socklen = socklen;
        text = ngx_pnalloc(new_pool, NGX_SOCKADDR_STRLEN);
        if (text == NULL) {
            ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
                "upstream-dynamic-servers: Error initializing sockaddr");
            ngx_destroy_pool(new_pool);
            goto end;
        }
        len = ngx_sock_ntop(sockaddr, socklen, text, NGX_SOCKADDR_STRLEN, 1);
        addr->name.len = len;
        addr->name.data = text;
        ngx_log_error(NGX_LOG_INFO, ctx->resolver->log, 0,
            "upstream-dynamic-servers: '%V' was resolved to '%V'", &ctx->name,
            &addr->name);
    }

    // If the domain failed to resolve, mark this server as down.
    dynamic_server->server->down = ctx->state ? 1 : 0;
    dynamic_server->server->addrs = addrs;
    dynamic_server->server->naddrs = ctx->naddrs;

    if (ngx_http_upstream_init_round_robin(
            &cf, dynamic_server->upstream_conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->resolver->log, 0,
            "upstream-dynamic-servers: Error re-initializing "
            "upstream after DNS changes");
    }
    dynamic_server->upstream_conf->peer.init =
        ngx_http_upstream_init_dynamic_server_peer;
    pool_queue = &dynamic_server->pool_queue;

    ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
        "upstream-dynamic-servers: upstream host '%V' pool_queue_len is %i "
        "before insert",
        &dynamic_server->upstream_conf->host, dynamic_server->pool_queue_len);

    for (p = pool_queue->next, n = p->next; p != pool_queue;
         p = n, n = n->next) {
        tmp_node = ngx_queue_data(
            p, ngx_http_upstream_dynamic_server_pool_node_t, queue);
        if (tmp_node->refer_num == 0) {
            ngx_queue_remove(p);

            ngx_log_debug(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                "upstream-dynamic-servers: upstream host '%V' %ith pool "
                "will be destoried",
                &dynamic_server->upstream_conf->host, index);
            ngx_log_error(NGX_LOG_DEBUG, ctx->resolver->log, 0,
                "destroy pool %p host:%s refer_num:%d", tmp_node,
                dynamic_server->server->host.data, tmp_node->refer_num);

            ngx_destroy_pool(tmp_node->pool);
            dynamic_server->pool_queue_len--;
        }
        index++;
    }

    ngx_queue_insert_tail(pool_queue, &pool_node->queue);
    dynamic_server->pool_queue_len++;

end:
    ngx_resolve_name_done(ctx);
    if (ngx_exiting) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "upstream-dynamic-servers: worker is about to exit, do "
            "not set the timer again");
        return;
    }
    if (dynamic_server->resolve_num == 0) {
        dynamic_server->resolve_num = 1;
        refresh_in = ngx_random() % 5000;
    }
    ngx_add_timer(&dynamic_server->timer, refresh_in);
}

static void
ngx_http_upstream_dynamic_servers_exit_process(ngx_cycle_t *cycle)
{
    ngx_uint_t                                    i;
    ngx_queue_t                                  *p, *n, *pool_queue;
    ngx_http_upstream_dynamic_server_main_conf_t *udsmcf;
    ngx_http_upstream_dynamic_server_pool_node_t *tmp_node;
    ngx_http_upstream_dynamic_server_conf_t      *dynamic_server;

    udsmcf = ngx_http_cycle_get_module_main_conf(
        ngx_cycle, ngx_http_upstream_dynamic_servers_module);
    if (udsmcf == NULL) {
        return;
    }

    dynamic_server = udsmcf->dynamic_servers.elts;
    for (i = 0; i < udsmcf->dynamic_servers.nelts; i++) {
        pool_queue = &dynamic_server[i].pool_queue;
        for (p = pool_queue->next, n = p->next; p != pool_queue;
             p = n, n = n->next) {
            tmp_node = ngx_queue_data(
                p, ngx_http_upstream_dynamic_server_pool_node_t, queue);
            ngx_queue_remove(p);
            ngx_destroy_pool(tmp_node->pool);
            dynamic_server[i].pool_queue_len--;
        }
    }
}

static void
ngx_http_upstream_dynamic_rbtree_server_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t **p;

    for (;;) {
        p = node->key < temp->key ? &temp->left : &temp->right;
        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

ngx_rbtree_node_t *
ngx_http_upstream_dynamic_server_rbtree_lookup(
    ngx_rbtree_t *rbtree, uint32_t hash, ngx_str_t *key)
{
    ngx_rbtree_node_t *node, *sentinel;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {
        if (node->key != hash) {
            node = (node->key > hash) ? node->left : node->right;
            continue;
        } else {
            return node;
        }
    }

    return NULL;
}