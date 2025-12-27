#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include "ngx_http_ja4_module.h"

// Forward declarations
static ngx_int_t ngx_http_ja4_add_variables(ngx_conf_t *cf);
static void *ngx_http_ja4_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// Global index for storing our context in SSL object
static int ngx_ja4_ssl_ex_index = -1;

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

static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r);
void ngx_ja4_calculate(ngx_connection_t *c, ngx_ssl_ja4_t *ja4);

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
    NULL,                          /* init process */
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
    // Arrays will be allocated on demand or we can init here? 
    // Usually on demand in handler is fine, or here.
    return conf;
}

static char *ngx_http_ja4_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_ja4_srv_conf_t *prev = parent;
    ngx_http_ja4_srv_conf_t *conf = child;
    
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    
    // Merge rules? Usually we inherit if child is empty.
    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }
    if (conf->rules_h == NULL) {
        conf->rules_h = prev->rules_h;
    }
     if (conf->rules_one == NULL) {
        conf->rules_one = prev->rules_one;
    }

    return NGX_CONF_OK;
}

static char *ngx_http_ja4_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ja4_srv_conf_t *jcf = conf;
    ngx_str_t *value;
    ngx_http_ja4_rule_t *rule;
    ngx_array_t **rules_ptr;
    
    value = cf->args->elts;
    
    // Determine which array to use based on directive name
    if (ngx_strstr(cmd->name.data, (u_char *)"ja4h_")) {
        rules_ptr = &jcf->rules_h;
    } else if (ngx_strstr(cmd->name.data, (u_char *)"ja4one_")) {
        rules_ptr = &jcf->rules_one;
    } else {
        // default ja4_
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

// Variables
static ngx_http_variable_t  ngx_http_ja4_vars[] = {
    { ngx_string("http_ssl_ja4"), NULL, ngx_http_ja4_variable, 0, 0, 0 },
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

// Initialization and Hooking
static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf) {
    // 1. Get global ex index
    ngx_ja4_ssl_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ngx_ja4_ssl_ex_index == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ja4: Failed to get SSL ex index");
        return NGX_ERROR;
    }

    // 2. Add Access Phase Handler
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt *h;
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_ja4_access_handler;


    // 3. Iterate servers and add ClientHello Callback
    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    ngx_uint_t s;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        // We need to access the SSL module config for this server
         ngx_http_ssl_srv_conf_t *sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
         
         if (sscf && sscf->ssl.ctx) {
             SSL_CTX_set_client_hello_cb(sscf->ssl.ctx, ngx_ja4_client_hello_cb, NULL);
         }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_access_handler(ngx_http_request_t *r) {
    ngx_http_ja4_srv_conf_t *jcf;
    
    // Check if SSL
    if (!r->connection || !r->connection->ssl) return NGX_DECLINED;

    jcf = ngx_http_get_module_srv_conf(r, ngx_http_ja4_module);
    
    // Check JA4 Rules
    if (jcf->rules) {
        ngx_ja4_ssl_ctx_t *ctx;
        ngx_uint_t i;
        ngx_http_ja4_rule_t *rules;
        SSL *ssl;
        u_char buf[65];
        u_char *last;
        ngx_str_t fp;

        // Need to calculate JA4 fingerprint first
        ssl = r->connection->ssl->connection;
        ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
        
        if (ctx && ctx->ja4_data) {
             if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
                ngx_ja4_calculate(r->connection, ctx->ja4_data);
            }
             
            // Format Output for comparison
            
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
                     // If allow match, allow access
                     return NGX_OK; 
                 }
            }
        }
    }
    
    // TODO: JA4H and JA4one checks would go here similarly
    
    return NGX_DECLINED;
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

    } else {
         ngx_memcpy(ja4->cipher_hash_truncated, "000000000000", 12);
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
        
        raw_count = 0;
        for (j = 0; j < ja4->extensions_sz; j++) {
            if (!ngx_ja4_is_grease(ja4->extensions[j])) raw_count++;
        }
        ja4->extensions_sz = raw_count;

    } else {
        ngx_memcpy(ja4->extension_hash_truncated, "000000000000", 12);
    }
}

static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    if (!r->connection || !r->connection->ssl) return NGX_OK;
    
    SSL *ssl = r->connection->ssl->connection;
    ngx_ja4_ssl_ctx_t *ctx = SSL_get_ex_data(ssl, ngx_ja4_ssl_ex_index);
    
    if (!ctx || !ctx->ja4_data) {
        // No data collected (callback didn't run or failed)
        v->not_found = 1;
        return NGX_OK;
    }
    
    // Perform calculation if not done
    // We can check if version is set '13' etc. If char* is < 100 it is still int
    if ((uintptr_t)ctx->ja4_data->highest_supported_tls_client_version < 65535) {
        ngx_ja4_calculate(r->connection, ctx->ja4_data);
    }

    // Format Output
    u_char *p = ngx_pnalloc(r->pool, 64); // t13d...
    if (p == NULL) return NGX_ERROR;
    
    u_char *last = ngx_snprintf(p, 64, "%c%s%c%02d%02d_%s_%s",
        ctx->ja4_data->transport,
        ctx->ja4_data->version,
        ctx->ja4_data->has_sni,
        ctx->ja4_data->ciphers_sz,
        ctx->ja4_data->extensions_sz,
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
