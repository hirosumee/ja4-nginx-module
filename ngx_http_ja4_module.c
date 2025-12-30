#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "ngx_http_ja4_module.h"
#include <ngx_http_v2.h>

#if (NGX_GCC)
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#endif
#ifndef TCP_SAVED_SYN
#define TCP_SAVED_SYN 28
#endif


// Global index for storing our context in SSL object
int ngx_ja4_ssl_ex_index = -1;

// Forward declarations
static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf);
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_ja4_init_process(ngx_cycle_t *cycle);


static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


// Grease and Ignore lists (copied from original)
static const char *GREASE[] = {
    "0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a",
    "8a8a", "9a9a", "aaaa", "baba", "caca", "dada", "eaea", "fafa",
};

/* Unused in simplified version - NOW USED */
static const char *EXT_IGNORE_DYNAMIC[] = {
    "0029", // PRE_SHARED_KEY
    "0015", // PADDING
};

static const char *EXT_IGNORE[] = {
    "0000", // SNI
    "0010", // ALPN
};

static int ngx_ja4_is_grease(const char *ext) {
    for (size_t i = 0; i < sizeof(GREASE)/sizeof(char*); i++) {
        if (strcmp(ext, GREASE[i]) == 0) return 1;
    }
    return 0;
}

static int ngx_ja4_is_dynamic(const char *ext) {
    for (size_t i = 0; i < sizeof(EXT_IGNORE_DYNAMIC)/sizeof(char*); i++) {
        if (strcmp(ext, EXT_IGNORE_DYNAMIC[i]) == 0) return 1;
    }
    return 0;
}

static int ngx_ja4_is_ignored(const char *ext) {
    for (size_t i = 0; i < sizeof(EXT_IGNORE)/sizeof(char*); i++) {
        if (strcmp(ext, EXT_IGNORE[i]) == 0) return 1;
    }
    return 0;
}

static int compare_hexes(const void *a, const void *b) {
    const char *ext_a = *(const char **)a;
    const char *ext_b = *(const char **)b;
    unsigned int hex_a = strtoul(ext_a, NULL, 16);
    unsigned int hex_b = strtoul(ext_b, NULL, 16);
    if (hex_a < hex_b) return -1;
    if (hex_a > hex_b) return 1;
    return 0;
}


// Client Hello Callback
// This replaces the patch logic
int ngx_ja4_client_hello_cb(SSL *s, int *al, void *arg) {
    ngx_connection_t *c;
    ngx_ja4_ssl_ctx_t *ctx;
    int *ext_out;
    size_t ext_len;
    
    c = SSL_get_ex_data(s, ngx_ssl_connection_index);
    if (c == NULL) {
        return 1;
    }

    // Allocate our context
    ctx = ngx_pcalloc(c->pool, sizeof(ngx_ja4_ssl_ctx_t));
    if (ctx == NULL) return 0; // Error

    ctx->pool = c->pool;
    ctx->ja4_data = ngx_pcalloc(c->pool, sizeof(ngx_ssl_ja4_t));
    if (ctx->ja4_data == NULL) return 0;

    SSL_set_ex_data(s, ngx_ja4_ssl_ex_index, ctx);

    // --- LOGIC PORTED FROM PATCH ---
    if (!SSL_client_hello_get1_extensions_present(s, &ext_out, &ext_len)) {
        return 1;
    }
    if (!ext_out || !ext_len) { 
         if(ext_out) OPENSSL_free(ext_out);
         return 1; 
    }

    // Store raw extensions in our struct (temporarily imitating c->ssl->extensions from patch)
    
    ctx->ja4_data->extensions_sz = ext_len;
    ctx->ja4_data->extensions = ngx_pcalloc(c->pool, sizeof(char *) * ext_len);
    
    // Also capture highest version
    int highest_ver = 0;

    for (size_t i = 0; i < ext_len; i++) {
        char hex_str[6];
        ngx_snprintf((u_char*)hex_str, sizeof(hex_str), "%04x", ext_out[i]);
        
        ctx->ja4_data->extensions[i] = ngx_pcalloc(c->pool, 6);
        ngx_memcpy(ctx->ja4_data->extensions[i], hex_str, 5); // 4 hex + null

        // Supported Versions logic (0x002b)
        if (ext_out[i] == 0x002b) {
             const unsigned char *ver_data;
             size_t ver_len;
             if (SSL_client_hello_get0_ext(s, 0x002b, &ver_data, &ver_len) && ver_len >= 3) {
                 size_t list_len = ver_data[0];
                 const unsigned char *p = ver_data + 1;
                 for (size_t j = 0; j + 1 < list_len && (j+1 < ver_len); j += 2) {
                     int v = (p[j] << 8) | p[j+1];
                     if ((v & 0x0f0f) == 0x0a0a) continue; // Grease
                     if (v > highest_ver) highest_ver = v;
                 }
             }
        }
    }
    
    if (highest_ver == 0) {
        highest_ver = SSL_client_hello_get0_legacy_version(s);
    }
    
    ctx->ja4_data->highest_supported_tls_client_version = (char*)(uintptr_t)highest_ver; 

    OPENSSL_free(ext_out);
    return 1;
}

#define NGX_HTTP_JA4_ALLOW 1
#define NGX_HTTP_JA4_DENY  2

// Forward declarations
static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r);
void ngx_ja4_calculate(ngx_connection_t *c, ngx_ssl_ja4_t *ja4);
void ngx_ja4h_calculate(ngx_http_request_t *r, ngx_ssl_ja4h_t *ja4h);
void ngx_ja4one_calculate(ngx_http_request_t *r, ngx_ssl_ja4one_t *ja4one);
void ngx_ja4tcp_calculate(ngx_http_request_t *r, ngx_str_t *res);
void ngx_ja4s_calculate(ngx_http_request_t *r, ngx_ssl_ja4s_t *ja4s);


// --- Internal HTTP/2 Structure Definitions (Simulated) ---
// Since we don't have direct access to internal headers easily, we define necessary subsets.
// This matches standard NGINX 1.18+ structure beginning.
typedef struct {
    ngx_uint_t                      id;
    ngx_uint_t                      value;
} ngx_http_v2_setting_t;

typedef struct {
    ngx_connection_t               *connection;
    ngx_http_connection_t          *http_connection;
    ngx_uint_t                      processing;
    
    // In NGINX, settings are usually further down, but let's assume we can access them via offset or if we include the header?
    // Wait, reusing exact definition is risky if it changes.
    // However, for standard NGINX, accessing `init_window` is common.
    
    // We will attempt to rely on standard NGINX includes being available during build.
    // If this fails, we will need to revisit.
    // BUT since I am writing this into the file, I should define a "compatible" struct 
    // that mimics the layout just enough, or assume we can include the file.
} ngx_http_v2_connection_subset_t;
// NOTE: I will strictly rely on `ngx_http_v2_module.h` implicit availability or similar? No.
// I'll proceed with the assumption we can access `ngx_ssl_ja4s_t` logic.
// I'll add the logic now.




// Module Directives
static ngx_command_t ngx_http_ja4_commands[] = {
    { ngx_string("ja4"),
      NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ja4_srv_conf_t, enable),
      NULL },
      
    { ngx_string("ja4_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4h_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4h_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
      
    { ngx_string("ja4one_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4one_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4s_deny"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ja4s_allow"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_ja4_handler,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

// Module Context
static ngx_http_module_t ngx_http_ja4_module_ctx = {
    ngx_http_ja4_add_variables,    /* preconfiguration */
    ngx_http_ja4_init,             /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    ngx_http_ja4_create_srv_conf,  /* create server configuration */
    ngx_http_ja4_merge_srv_conf,   /* merge server configuration */
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ja4_module_ctx,      /* module context */
    ngx_http_ja4_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_ja4_init_process,     /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

// Config functions
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_ja4_srv_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ja4_srv_conf_t));
    if (conf == NULL) return NULL;
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_ja4_srv_conf_t *prev = parent;
    ngx_http_ja4_srv_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    
    if (conf->rules == NULL) conf->rules = prev->rules;
    if (conf->rules_h == NULL) conf->rules_h = prev->rules_h;
    if (conf->rules_one == NULL) conf->rules_one = prev->rules_one;
    if (conf->rules_s == NULL) conf->rules_s = prev->rules_s;

    return NGX_CONF_OK;
}

static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ja4_srv_conf_t *jcf = conf;
    ngx_str_t *value;
    ngx_http_ja4_rule_t *rule;
    ngx_array_t **rules_ptr;
    
    value = cf->args->elts;
    
    if (ngx_strstr(cmd->name.data, (u_char *)"ja4h_")) {
        rules_ptr = &jcf->rules_h;
    } else if (ngx_strstr(cmd->name.data, (u_char *)"ja4one_")) {
        rules_ptr = &jcf->rules_one;
    } else if (ngx_strstr(cmd->name.data, (u_char *)"ja4s_")) {
        rules_ptr = &jcf->rules_s;
    } else {
        rules_ptr = &jcf->rules;
    }
    
    if (*rules_ptr == NULL) {
        *rules_ptr = ngx_array_create(cf->pool, 4, sizeof(ngx_http_ja4_rule_t));
        if (*rules_ptr == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    rule = ngx_array_push(*rules_ptr);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }
    
    rule->name = value[1];
    
    if (ngx_strstr(cmd->name.data, (u_char *)"_allow")) {
        rule->type = NGX_HTTP_JA4_ALLOW;
    } else {
        rule->type = NGX_HTTP_JA4_DENY;
    }
    
    return NGX_CONF_OK;
}


static ngx_http_variable_t  ngx_http_ja4_vars[] = {
    { ngx_string("http_ssl_ja4"), NULL, ngx_http_ja4_variable, 0, 0, 0 },
    { ngx_string("http_ssl_ja4h"), NULL, ngx_http_ja4_variable, 1, 0, 0 },
    { ngx_string("http_ssl_ja4one"), NULL, ngx_http_ja4_variable, 2, 0, 0 },
    { ngx_string("http_ssl_ja4tcp"), NULL, ngx_http_ja4_variable, 3, 0, 0 },
    { ngx_string("http_ssl_ja4s"), NULL, ngx_http_ja4_variable, 4, 0, 0 },
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t *var, *v;
    for (v = ngx_http_ja4_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) return NGX_ERROR;
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_uint_t s;

    // 1. Get global ex index
    ngx_ja4_ssl_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ngx_ja4_ssl_ex_index == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ja4: Failed to get SSL ex index");
        return NGX_ERROR;
    }

    // 2. Add Access Phase Handler
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_ja4_access_handler;

    // 3. Iterate servers and add ClientHello Callback
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
         ngx_http_ssl_srv_conf_t *sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
         
         if (sscf && sscf->ssl.ctx) {
             SSL_CTX_set_client_hello_cb(sscf->ssl.ctx, ngx_ja4_client_hello_cb, NULL);
         }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init_process(ngx_cycle_t *cycle) {
    ngx_uint_t i;
    ngx_listening_t *ls;
    int optval = 1;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        // Only enable for TCP sockets
        if (ls[i].type == SOCK_STREAM) {
            if (setsockopt(ls[i].fd, IPPROTO_TCP, TCP_SAVE_SYN, &optval, sizeof(optval)) == -1) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno, 
                              "ja4: setsockopt(TCP_SAVE_SYN) failed for %V", &ls[i].addr_text);
            } else {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, 
                               "ja4: TCP_SAVE_SYN enabled for %V", &ls[i].addr_text);
            }
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r) {
    ngx_http_ja4_srv_conf_t *jcf;
    
    jcf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    
    // 1. JA4 Checks (Only if SSL)
    if (r->connection->ssl && jcf->rules) {
        ngx_ja4_ssl_ctx_t *ctx;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        SSL *ssl;
        u_char buf[65];
        u_char *last;
        ngx_str_t fp;

        ssl = r->connection->ssl->connection;
        ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (ctx && ctx->ja4_data) {
             if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
                ngx_ja4_calculate(r->connection, ctx->ja4_data);
            }
             
            last = ngx_snprintf(buf, 64, "%c%s%c%02d%02d_%s_%s",
                ctx->ja4_data->transport,
                ctx->ja4_data->version,
                ctx->ja4_data->has_sni,
                (int)ctx->ja4_data->ciphers_sz,
                (int)ctx->ja4_data->extensions_sz,
                ctx->ja4_data->cipher_hash_truncated,
                ctx->ja4_data->extension_hash_truncated
            );
            *last = '\0';
            
            fp.data = buf;
            fp.len = last - buf;
            
            rules = jcf->rules->elts;
            for (i = 0; i < jcf->rules->nelts; i++) {
                 if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                     if (rules[i].type == NGX_HTTP_JA4_DENY) {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4: %V", &fp);
                         return NGX_HTTP_FORBIDDEN;
                     }
                  }
             }
        }
    }
    
    // 2. JA4H Checks
    if (jcf->rules_h) {
        ngx_ssl_ja4h_t ja4h;
        u_char buf[65];
        u_char *last;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        
        ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
        
        ngx_ja4h_calculate(r, &ja4h);
        
        last = ngx_snprintf(buf, 64, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
        *last = '\0';
        
        fp.data = buf;
        fp.len = last - buf;
        
        rules = jcf->rules_h->elts;
        
        for (i = 0; i < jcf->rules_h->nelts; i++) {
             if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                 if (rules[i].type == NGX_HTTP_JA4_DENY) {
                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4H: %V", &fp);
                     return NGX_HTTP_FORBIDDEN;
                 }
             }
        }
    }

    // 3. JA4one Checks
    if (jcf->rules_one) {
        ngx_ssl_ja4one_t ja4one;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;

        ngx_ja4one_calculate(r, &ja4one);
        
        fp.data = (u_char*)ja4one.fingerprint;
        fp.len = ngx_strlen(ja4one.fingerprint);
        
        rules = jcf->rules_one->elts;
         for (i = 0; i < jcf->rules_one->nelts; i++) {
             if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                 if (rules[i].type == NGX_HTTP_JA4_DENY) {
                     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4one: %V", &fp);
                     return NGX_HTTP_FORBIDDEN;
                 }
             }
        }
    }

    // 4. JA4S Checks (HTTP/2)
    if (jcf->rules_s) {
        ngx_ssl_ja4s_t ja4s;
        ngx_str_t fp;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        
        ngx_memzero(&ja4s, sizeof(ngx_ssl_ja4s_t));
        
        ngx_ja4s_calculate(r, &ja4s);
        
        if (ja4s.fingerprint[0] != '\0') {
            fp.data = (u_char*)ja4s.fingerprint;
            fp.len = ngx_strlen(ja4s.fingerprint);
            
            rules = jcf->rules_s->elts;
            for (i = 0; i < jcf->rules_s->nelts; i++) {
                 if (rules[i].name.len == fp.len && ngx_strncmp(rules[i].name.data, fp.data, fp.len) == 0) {
                     if (rules[i].type == NGX_HTTP_JA4_DENY) {
                         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "access forbidden by JA4S: %V", &fp);
                         return NGX_HTTP_FORBIDDEN;
                     }
                 }
            }
        }
    }
    
    return NGX_DECLINED;
}
    

// Variables

// ... (existing code for add_variables)

static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_ja4_ssl_ctx_t *ctx;
    u_char *p;
    u_char *last;
    
    if (data == 0) { // JA4
        SSL *ssl;
        
        if (!r->connection || !r->connection->ssl) return NGX_OK; // Return empty if not SSL

        ssl = r->connection->ssl->connection;
        ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (!ctx || !ctx->ja4_data) {
            v->not_found = 1;
            return NGX_OK;
        }
        
        if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
            ngx_ja4_calculate(r->connection, ctx->ja4_data);
        }
        
        p = ngx_pnalloc(r->pool, 64);
        if (p == NULL) return NGX_ERROR;
        
        last = ngx_snprintf(p, 64, "%c%s%c%02d%02d_%s_%s",
            ctx->ja4_data->transport,
            ctx->ja4_data->version,
            ctx->ja4_data->has_sni,
            (int)ctx->ja4_data->ciphers_sz,
            (int)ctx->ja4_data->extensions_sz,
            ctx->ja4_data->cipher_hash_truncated,
            ctx->ja4_data->extension_hash_truncated
        );
        
        v->len = last - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }
    else if (data == 1) { // JA4H
        ngx_ssl_ja4h_t ja4h;
        ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
        
        ngx_ja4h_calculate(r, &ja4h);
        
        p = ngx_pnalloc(r->pool, 64);
        if (p == NULL) return NGX_ERROR;
        // MMVVCHH_HHHH...
        last = ngx_snprintf(p, 64, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
            
        v->len = last - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }
    else if (data == 2) { // JA4one
         ngx_ssl_ja4one_t ja4one;
         ngx_ja4one_calculate(r, &ja4one);
         
         p = ngx_pnalloc(r->pool, 64);
         if (p == NULL) return NGX_ERROR;
         
         last = ngx_snprintf(p, 64, "%s", ja4one.fingerprint);
         v->len = last - p;
         v->data = p;
         v->valid = 1;
         v->no_cacheable = 0;
         v->not_found = 0;
         return NGX_OK;
    }

    else if (data == 3) { // JA4TCP
        ngx_str_t res;
        ngx_ja4tcp_calculate(r, &res);
        
        if (res.len == 0) {
            v->not_found = 1;
            return NGX_OK;
        }

        v->len = res.len;
        v->data = res.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }
    
    else if (data == 4) { // JA4S
        ngx_ssl_ja4s_t ja4s;
        ngx_memzero(&ja4s, sizeof(ngx_ssl_ja4s_t));
        
        ngx_ja4s_calculate(r, &ja4s);
        
        if (ja4s.fingerprint[0] == '\0') {
            v->not_found = 1;
            return NGX_OK;
        }

        v->len = ngx_strlen(ja4s.fingerprint);
        v->data = ngx_pnalloc(r->pool, v->len + 1);
        if (v->data == NULL) return NGX_ERROR;
        ngx_memcpy(v->data, ja4s.fingerprint, v->len);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        return NGX_OK;
    }

    return NGX_ERROR;
}

// ... (access handler updates will come in next step or I can do it here logic-wise)
// I will keep access handler logic separate for clarity if possible, or merge it. 
// The prompt asked for "JA4H Calculation Logic".

// --- CALCULATION LOGIC ---

void ngx_ja4h_calculate(ngx_http_request_t *r, ngx_ssl_ja4h_t *ja4h) {
    // 1. Method
    if (r->method & NGX_HTTP_GET) ngx_memcpy(ja4h->method, "ge", 2);
    else if (r->method & NGX_HTTP_POST) ngx_memcpy(ja4h->method, "po", 2);
    else if (r->method & NGX_HTTP_PUT) ngx_memcpy(ja4h->method, "pu", 2);
    else if (r->method & NGX_HTTP_DELETE) ngx_memcpy(ja4h->method, "de", 2);
    else if (r->method & NGX_HTTP_HEAD) ngx_memcpy(ja4h->method, "he", 2);
    else if (r->method & NGX_HTTP_OPTIONS) ngx_memcpy(ja4h->method, "op", 2);
    else if (r->method & NGX_HTTP_TRACE) ngx_memcpy(ja4h->method, "tr", 2);
    else if (r->method & NGX_HTTP_PATCH) ngx_memcpy(ja4h->method, "pa", 2);
    else ngx_memcpy(ja4h->method, "xx", 2);
    
    // 2. Version
    if (r->http_version == NGX_HTTP_VERSION_11) ngx_memcpy(ja4h->version, "11", 2);
    else if (r->http_version == NGX_HTTP_VERSION_10) ngx_memcpy(ja4h->version, "10", 2);
    else if (r->http_version == NGX_HTTP_VERSION_20) ngx_memcpy(ja4h->version, "20", 2);
    else if (r->http_version == NGX_HTTP_VERSION_30) ngx_memcpy(ja4h->version, "30", 2);
    else ngx_memcpy(ja4h->version, "00", 2);
    
// 2. Cookie & 4. Headers
    {
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h = part->elts;
    ngx_uint_t i;
    SHA256_CTX sha256;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int first = 1;

    ja4h->cookie = 'n';
    ja4h->header_count = 0;
    
    // For hashing
    SHA256_Init(&sha256);
    
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            h = part->elts;
            i = 0;
        }
        
        // Check for Cookie
        if (h[i].key.len == 6 && ngx_strncasecmp(h[i].key.data, (u_char *)"Cookie", 6) == 0) {
            ja4h->cookie = 'c';
        }
        
        // Add to Hash (Key only)
        if (!first) {
            SHA256_Update(&sha256, ",", 1);
        }
        SHA256_Update(&sha256, h[i].key.data, h[i].key.len);
        first = 0;
        
        ja4h->header_count++;
    }
    
    
    
    SHA256_Final(hash, &sha256);
    ngx_hex_dump((u_char*)ja4h->header_hash, hash, 32); // Full SHA256 (64 chars)
    }
}

void ngx_ja4one_calculate(ngx_http_request_t *r, ngx_ssl_ja4one_t *ja4one) {
    // Placeholder logic for JA4one: Hash(JA4H + JA4)
    // For now purely experimental
    char ja4_part[128] = "";
    char ja4h_part[128];
    
    u_char *last;
    
    // 1. Get JA4H
    ngx_ssl_ja4h_t ja4h;
    ngx_memzero(&ja4h, sizeof(ngx_ssl_ja4h_t));
    ngx_ja4h_calculate(r, &ja4h);
    
    last = ngx_snprintf((u_char*)ja4h_part, 128, "%s%s%c%02d_%s", 
            ja4h.method, ja4h.version, ja4h.cookie, ja4h.header_count, ja4h.header_hash);
    *last = '\0';
            
    // 2. Get JA4 (if SSL)
    if (r->connection->ssl) {
        SSL *ssl = r->connection->ssl->connection;
        ngx_ja4_ssl_ctx_t *ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (ctx && ctx->ja4_data) {
             if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
                ngx_ja4_calculate(r->connection, ctx->ja4_data);
            }
             last = ngx_snprintf((u_char*)ja4_part, 128, "%c%s%c%02d%02d_%s_%s_",
                ctx->ja4_data->transport,
                ctx->ja4_data->version,
                ctx->ja4_data->has_sni,
                (int)ctx->ja4_data->ciphers_sz,
                (int)ctx->ja4_data->extensions_sz,
                ctx->ja4_data->cipher_hash,
                ctx->ja4_data->extension_hash
            );
            *last = '\0';
        }
    }
    
    // 3. Combine
    // JA4one = JA4 + JA4H
    // If no JA4, matches just JA4H (or we could prefix with delimiter)
    
    u_char final_buf[256];
    last = ngx_snprintf(final_buf, 256, "%s%s", ja4_part, ja4h_part);
    *last = '\0';
    
    ngx_memcpy(ja4one->fingerprint, final_buf, ngx_strlen(final_buf) + 1);
}

// ------ JA4 CALCULATION LOGIC ------

void ngx_ja4_calculate(ngx_connection_t *c, ngx_ssl_ja4_t *ja4) {
    SSL *ssl = c->ssl->connection;
    ngx_pool_t *pool = c->pool;
    
    int max_ver, client_ver, ver;
    STACK_OF(SSL_CIPHER) *cp;
    int num_ciphers, i, id;
    const SSL_CIPHER *c_obj;
    char hex[5];
    SHA256_CTX sha256;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    char **filtered_exts;
    size_t count, raw_count, j;
    char *ext;
    
    // 1. Version
    max_ver = (int)(uintptr_t)ja4->highest_supported_tls_client_version;
    client_ver = SSL_client_version(ssl);
    ver = max_ver ? max_ver : client_ver;
    
    switch (ver) {
        case TLS1_3_VERSION_INT: ja4->version = "13"; break;
        case TLS1_2_VERSION_INT: ja4->version = "12"; break;
        case TLS1_1_VERSION_INT: ja4->version = "11"; break;
        case TLS1_VERSION_INT:   ja4->version = "10"; break;
        default:                 ja4->version = "00"; break;
    }
    
    ja4->transport = (c->quic) ? 'q' : 't';
    ja4->has_sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) ? 'd' : 'i';

    // 2. Ciphers
    cp = SSL_get_client_ciphers(ssl);
    if (cp) {
        ja4->ciphers_sz = 0;
        num_ciphers = sk_SSL_CIPHER_num(cp);
        ja4->ciphers = ngx_pnalloc(pool, num_ciphers * sizeof(char*));
        
        // Populate and Filter
        for (i = 0; i < num_ciphers; i++) {
             c_obj = sk_SSL_CIPHER_value(cp, i);
             id = SSL_CIPHER_get_protocol_id(c_obj);
             
             ngx_snprintf((u_char*)hex, 5, "%04x", id);
             
             if (ngx_ja4_is_grease(hex)) continue;
             
             ja4->ciphers[ja4->ciphers_sz] = ngx_pnalloc(pool, 5);
             ngx_memcpy(ja4->ciphers[ja4->ciphers_sz], hex, 5);
             ja4->ciphers_sz++;
        }
        
        // Sort Ciphers
        qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(char*), compare_hexes);
        
        // Hash Ciphers
        SHA256_Init(&sha256);
        for (j = 0; j < ja4->ciphers_sz; j++) {
            SHA256_Update(&sha256, ja4->ciphers[j], 4);
            if (j < ja4->ciphers_sz - 1) {
                SHA256_Update(&sha256, ",", 1);
            }
        }
        SHA256_Final(hash, &sha256);
        
        ngx_hex_dump((u_char*)ja4->cipher_hash_truncated, hash, 6);
        ngx_hex_dump((u_char*)ja4->cipher_hash, hash, 32); 

    } else {
         ngx_memcpy(ja4->cipher_hash_truncated, "000000000000", 12);
         ngx_memset(ja4->cipher_hash, '0', 64);
         ja4->cipher_hash[64] = '\0';
    }
    
    // 3. Extensions Hashing
    if (ja4->extensions_sz > 0) {
        // We have raw extensions in ja4->extensions.
        filtered_exts = ngx_pnalloc(pool, ja4->extensions_sz * sizeof(char*));
        count = 0;
        
        for (j = 0; j < ja4->extensions_sz; j++) {
            ext = ja4->extensions[j];
            if (ngx_ja4_is_grease(ext) || ngx_ja4_is_ignored(ext) || ngx_ja4_is_dynamic(ext)) continue;
            
            filtered_exts[count] = ext;
            count++;
        }
        
        // Sort
        qsort(filtered_exts, count, sizeof(char*), compare_hexes);
        
        // Hash
        SHA256_Init(&sha256);
        for (j = 0; j < count; j++) {
            SHA256_Update(&sha256, filtered_exts[j], 4);
            if (j < count - 1) {
                SHA256_Update(&sha256, ",", 1);
            }
        }
        SHA256_Final(hash, &sha256);
        
        ngx_hex_dump((u_char*)ja4->extension_hash_truncated, hash, 6);
        ngx_hex_dump((u_char*)ja4->extension_hash, hash, 32);
        
        raw_count = 0;
        for (j = 0; j < ja4->extensions_sz; j++) {
            if (!ngx_ja4_is_grease(ja4->extensions[j])) raw_count++;
        }
        ja4->extensions_sz = raw_count;

    } else {
        ngx_memcpy(ja4->extension_hash_truncated, "000000000000", 12);
        ngx_memset(ja4->extension_hash, '0', 64);
        ja4->extension_hash[64] = '\0';
    }
}

void ngx_ja4tcp_calculate(ngx_http_request_t *r, ngx_str_t *res) {
    u_char buf[1024];
    socklen_t len = sizeof(buf);
    int fd;
    u_char *p, *tcp_hdr, *opts;
    u_char *last;
    int ip_ver, ip_hdr_len, tcp_hdr_len;
    uint16_t src_port, dst_port, window;
    uint32_t seq, ack;
    int mss = 0, scale = 0;
    u_char opt_kinds[64];
    int opt_count = 0;
    int i;
    u_char *out_buf;

    res->len = 0;
    res->data = NULL;

    if (!r->connection) return;
    fd = r->connection->fd;

    if (getsockopt(fd, IPPROTO_TCP, TCP_SAVED_SYN, buf, &len) == -1) {
        // Failed getting SYN, maybe not enabled or not Linux
        return;
    }
    
    // Parse IP Header
    if (len < 20) return;
    ip_ver = (buf[0] >> 4);
    
    if (ip_ver == 4) {
        ip_hdr_len = (buf[0] & 0x0F) * 4;
    } else if (ip_ver == 6) {
        ip_hdr_len = 40;
    } else {
        return; // Unknown IP version
    }
    
    if (len < ip_hdr_len + 20) return;
    
    tcp_hdr = buf + ip_hdr_len;
    
    // TCP Header:
    // Source Port (2), Dest Port (2), Seq (4), Ack (4), Offset/Flags (2), Window (2)
    // Offset is high 4 bits of byte 12
    tcp_hdr_len = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
    
    if (len < ip_hdr_len + tcp_hdr_len) return;
    
    window = (tcp_hdr[14] << 8) | tcp_hdr[15];
    
    // Parse Options
    if (tcp_hdr_len > 20) {
        opts = tcp_hdr + 20;
        int opt_len = tcp_hdr_len - 20;
        int idx = 0;
        
        while (idx < opt_len) {
            uint8_t kind = opts[idx];
            
            if (kind == 0) break; // EOL
            
            // Record NOP (kind 1) as well (JA4T standard requires it)
            if (kind == 1) { // NOP
                if (opt_count < 63) {
                    opt_kinds[opt_count++] = kind;
                }
                idx++;
                continue;
            }
            
            if (idx + 1 >= opt_len) break;
            uint8_t length = opts[idx+1];
            if (length < 2 || idx + length > opt_len) break;
            
            // Collect Option Kind
            if (opt_count < 63) {
                opt_kinds[opt_count++] = kind;
            }
            
            // Extract specific values
            if (kind == 2 && length == 4) { // MSS
                mss = (opts[idx+2] << 8) | opts[idx+3];
            } else if (kind == 3 && length == 3) { // Window Scale
                scale = opts[idx+2];
            }
            
            idx += length;
        }
    }
    
    // Format: w_o_m_s (JA4T standard)
    // w: Window (decimal)
    // o: Options list (decimal, dash-separated, including NOPs)
    // m: MSS (decimal)
    // s: Scale (decimal)
    
    out_buf = ngx_pnalloc(r->pool, 256);
    if (out_buf == NULL) return;
    
    last = ngx_snprintf(out_buf, 256, "%d_", window);
    
    // Output options as decimal-dash format (e.g., 2-1-3-1-1-4)
    if (opt_count > 0) {
        for (i = 0; i < opt_count; i++) {
            if (i > 0) {
                last = ngx_snprintf(last, 256 - (last - out_buf), "-");
            }
            last = ngx_snprintf(last, 256 - (last - out_buf), "%d", (int)opt_kinds[i]);
        }
    } else {
        last = ngx_snprintf(last, 256 - (last - out_buf), "0");
    }
    
    last = ngx_snprintf(last, 256 - (last - out_buf), "_%d_%d", mss, scale);
    

    
    res->data = out_buf;
    res->len = last - out_buf;
}





// HTTP/2 Setting IDs (Standard RFC 7540)
#define JA4S_SETTING_HEADER_TABLE_SIZE      0x1
#define JA4S_SETTING_ENABLE_PUSH            0x2
#define JA4S_SETTING_MAX_CONCURRENT_STREAMS 0x3
#define JA4S_SETTING_INITIAL_WINDOW_SIZE    0x4
#define JA4S_SETTING_MAX_FRAME_SIZE         0x5
#define JA4S_SETTING_MAX_HEADER_LIST_SIZE   0x6

typedef struct {
    uint32_t id;
    uint32_t val;
} ngx_ja4s_setting_pair_t;

static int ngx_ja4s_cmp_pair(const void *a, const void *b) {
    return (int)(((const ngx_ja4s_setting_pair_t *)a)->id - ((const ngx_ja4s_setting_pair_t *)b)->id);
}

void ngx_ja4s_calculate(ngx_http_request_t *r, ngx_ssl_ja4s_t *ja4s) {
    ngx_http_v2_stream_t *stream;
    ngx_http_v2_connection_t *h2c;
    ngx_ja4s_setting_pair_t pairs[32];
    uint32_t cnt;
    uint32_t i;
    u_char buf[1024];
    u_char *p, *last;
    u_char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    // 1. Check HTTP/2 Version (Robust check)
    if (r->http_version < NGX_HTTP_VERSION_20) {
        return;
    }
    
    // 2. Access Internal Structures (Safe with Patch)
    if (r->stream == NULL) return;
    
    stream = r->stream;
    h2c = stream->connection;
    
    if (h2c == NULL) return;

    // 3. Process Settings (No-Patch / Reconstruction Mode)
    // Since we cannot patch NGINX to capture raw settings, we reconstruct the known settings
    // from the connection state. This loses "Order" and "Unknown/Grease" settings,
    // but ensures upgrade compatibility.
    
    cnt = 0;
    
    // Setting 1: INITIAL_WINDOW_SIZE (ID 4)
    // h2c->init_window tracks valid window size
    pairs[cnt].id = JA4S_SETTING_INITIAL_WINDOW_SIZE;
    pairs[cnt].val = (uint32_t)h2c->init_window;
    cnt++;
    
    // Setting 2: MAX_FRAME_SIZE (ID 5)
    // h2c->frame_size tracks frame size
    pairs[cnt].id = JA4S_SETTING_MAX_FRAME_SIZE;
    pairs[cnt].val = (uint32_t)h2c->frame_size;
    cnt++;
    
    // Setting 3: HEADER_TABLE_SIZE (ID 1)
    // h2c->hpack.size tracks table size? NGINX uses dynamic table but stores limit?
    // h2c->hpack.size seems to be current size.
    // NGINX doesn't store the SETTING value if it's strictly internal. 
    // We will skip it to be safe, or include if we can verify correctness.
    // For now, we stick to robust fields.
    
    // Sort logic (Strictly by ID for consistency)
    qsort(pairs, cnt, sizeof(ngx_ja4s_setting_pair_t), ngx_ja4s_cmp_pair);
    
    // Generate Hash String: id:val,id:val,...
    p = buf;
    last = buf + sizeof(buf);
    
    for (i = 0; i < cnt; i++) {
        if (i > 0) {
            p = ngx_snprintf(p, last - p, ",");
        }
        p = ngx_snprintf(p, last - p, "%ui:%ui", (ngx_uint_t)pairs[i].id, (ngx_uint_t)pairs[i].val);
    }
    
    // SHA256
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buf, p - buf);
    SHA256_Final(hash, &sha256);
    
    // Truncate Hash (12 chars = 6 bytes hex)
    ngx_hex_dump((u_char*)ja4s->settings_hash, hash, 6);
    ja4s->settings_hash[12] = '\0'; 
    
    // 4. Construct Final Fingerprint
    // Format: h2<ProtoVer>_<Count>_<Hash>_<InitWindow>_<ParamOrder?>_<Priority?>
    
    ngx_snprintf((u_char*)ja4s->fingerprint, 255, "h220_%02d_%s_%uz_0", 
                 cnt, 
                 ja4s->settings_hash,
                 h2c->init_window); 
}

