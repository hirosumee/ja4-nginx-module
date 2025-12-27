#ifndef _NGX_HTTP_JA4_MODULE_H_INCLUDED_
#define _NGX_HTTP_JA4_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <openssl/ssl.h>

// Struct to store JA4 data attached to the SSL Connection via ex_data
typedef struct {
    ngx_pool_t *pool;
    // We can store the raw ja4 struct here
    // Note: We need to define ngx_ssl_ja4_t first, so I'll move this typedef below or forward declare
    struct ngx_ssl_ja4_s *ja4_data; 
} ngx_ja4_ssl_ctx_t;


typedef struct {
    ngx_str_t   ja4;
    ngx_str_t   ja4_string;
    ngx_str_t   ja4one;
    ngx_str_t   ja4h;
} ngx_http_ja4_ctx_t;

// STRUCTS
typedef struct ngx_ssl_ja4_s
{
    char *version; // TLS version
    char *highest_supported_tls_client_version;

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz; // Count of ciphers
    char **ciphers;    // List of ciphers

    size_t extensions_count; // Count of extensions including ignored extensions
    size_t extensions_sz; // Count of extensions NOT including ignored extensions
    char **extensions;    // List of extensions

    size_t extensions_no_psk_count;
    char **extensions_no_psk;

    char extension_hash_no_psk[65];
    char extension_hash_no_psk_truncated[13];

    size_t sigalgs_sz;
    char **sigalgs;

    char *alpn_first_value;

    char cipher_hash[65];
    char cipher_hash_truncated[13];

    char extension_hash[65];
    char extension_hash_truncated[13];

} ngx_ssl_ja4_t;

typedef struct ngx_ssl_ja4s_s {
    // keeping placeholders to avoid compilation errors if referenced
    int dummy;
} ngx_ssl_ja4s_t;

typedef struct ngx_ssl_ja4h_s {
     // keeping placeholders
     int dummy;
} ngx_ssl_ja4h_t;

typedef struct ngx_ssl_ja4t_s { int dummy; } ngx_ssl_ja4t_t;
typedef struct ngx_ssl_ja4ts_s { int dummy; } ngx_ssl_ja4ts_t;
typedef struct ngx_ssl_ja4x_s { int dummy; } ngx_ssl_ja4x_t;
typedef struct ngx_ssl_ja4l_s { int dummy; } ngx_ssl_ja4l_t;


// CONSTANTS
#define SSL3_VERSION_INT    0x0300
#define TLS1_VERSION_INT    0x0301
#define TLS1_1_VERSION_INT  0x0302
#define TLS1_2_VERSION_INT  0x0303
#define TLS1_3_VERSION_INT  0x0304
#define QUICV1_VERSION_INT  0x0001


// Configuration structs
typedef struct {
    ngx_flag_t  enable;
} ngx_http_ja4_srv_conf_t;

#endif
