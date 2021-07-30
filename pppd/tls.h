#ifndef TLS_H
#define TLS_H

/**
 * Structure used in verifying the peer certificate
 */
struct tls_info;

/**
 * Initialize the SSL library
 */
int tls_init();

/**
 * Get the SSL_METHOD
 */
const SSL_METHOD* tls_method();

/**
 * Configure the SSL options
 */
int tls_set_opts(SSL_CTX *ctx);

/**
 * Configure the SSL context's max TLS version
 */
int tls_set_version(SSL_CTX *ctx, const char *max_version);

/** 
 * Configure the SSL context's verify callback
 */
int tls_set_verify(SSL_CTX *ctx, int depth);

/**
 * Configure the SSL verify information
 */
int tls_set_verify_info(SSL *ssl, const char *peer_name, const char *peer_cert_file, 
        bool client, struct tls_info **out);

/**
 * Free the tls_info structure and it's members
 */
void tls_free_verify_info(struct tls_info **in);

/**
 * Configure the SSL context's CRL details
 */
int tls_set_crl(SSL_CTX *ctx, const char *crl_dir, const char *crl_file);

/**
 * Configure the SSL context's CA verify locations
 */
int tls_set_ca(SSL_CTX *ctx, const char *ca_dir, const char *ca_file);

/**
 * Log all errors from ssl library
 */
void tls_log_sslerr( void );

#endif	/* TLS_H */
