/* * eap-tls.c - EAP-TLS implementation for PPP
 *
 * Copyright (c) Beniamino Galvani 2005 All rights reserved.
 *               Jan Just Keijser  2006-2019 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>

#include "pppd.h"
#include "eap.h"
#include "eap-tls.h"
#include "fsm.h"
#include "lcp.h"
#include "chap_ms.h"
#include "mppe.h"
#include "pathnames.h"

typedef struct pw_cb_data
{
    const void *password;
    const char *prompt_info;
} PW_CB_DATA;

#ifndef OPENSSL_NO_ENGINE
/* The openssl configuration file and engines can be loaded only once */
static CONF   *ssl_config  = NULL;
static ENGINE *cert_engine = NULL;
static ENGINE *pkey_engine = NULL;
#endif

/* TLSv1.3 do we have a session ticket ? */
static int have_session_ticket = 0;

int ssl_verify_callback(int, X509_STORE_CTX *);
void ssl_msg_callback(int write_p, int version, int ct, const void *buf,
              size_t len, SSL * ssl, void *arg);
int ssl_new_session_cb(SSL *s, SSL_SESSION *sess);

X509 *get_X509_from_file(char *filename);
int ssl_cmp_certs(char *filename, X509 * a); 

/*
 *  OpenSSL 1.1+ introduced a generic TLS_method()
 *  For older releases we substitute the appropriate method
 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define TLS_method SSLv23_method

#define SSL3_RT_HEADER  0x100

#ifndef SSL_CTX_set_max_proto_version
/** Mimics SSL_CTX_set_max_proto_version for OpenSSL < 1.1 */
static inline int SSL_CTX_set_max_proto_version(SSL_CTX *ctx, long tls_ver_max)
{
    long sslopt = 0;

    if (tls_ver_max < TLS1_VERSION)
    {
        sslopt |= SSL_OP_NO_TLSv1;
    }
#ifdef SSL_OP_NO_TLSv1_1
    if (tls_ver_max < TLS1_1_VERSION)
    {
        sslopt |= SSL_OP_NO_TLSv1_1;
    }
#endif
#ifdef SSL_OP_NO_TLSv1_2
    if (tls_ver_max < TLS1_2_VERSION)
    {
        sslopt |= SSL_OP_NO_TLSv1_2;
    }
#endif
    SSL_CTX_set_options(ctx, sslopt);

    return 1;
}
#endif /* SSL_CTX_set_max_proto_version */

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef MPPE
#define EAPTLS_MPPE_KEY_LEN     32

/*
 *  Generate keys according to RFC 2716 and add to reply
 */
void eaptls_gen_mppe_keys(struct eaptls_session *ets, int client)
{
    unsigned char  out[4*EAPTLS_MPPE_KEY_LEN];
    const char    *prf_label;
    size_t         prf_size;
    unsigned char  eap_tls13_context[] = { EAPT_TLS };
    unsigned char *context = NULL;
    size_t         context_len = 0;
    unsigned char *p;

    dbglog("EAP-TLS generating MPPE keys");
    if (ets->tls_v13)
    {
        prf_label = "EXPORTER_EAP_TLS_Key_Material";
        context   = eap_tls13_context;
        context_len = 1;
    }
    else
    {
        prf_label = "client EAP encryption";
    }

    dbglog("EAP-TLS PRF label = %s", prf_label);
    prf_size = strlen(prf_label);
    if (SSL_export_keying_material(ets->ssl, out, sizeof(out), prf_label, prf_size, 
                                   context, context_len, 0) != 1)
    {
        warn( "EAP-TLS: Failed generating keying material" );
        return;
    }   

    /* 
     * We now have the master send and receive keys.
     * From these, generate the session send and receive keys.
     * (see RFC3079 / draft-ietf-pppext-mppe-keys-03.txt for details)
     */
    if (client)
    {
        mppe_set_keys(out, out + EAPTLS_MPPE_KEY_LEN, EAPTLS_MPPE_KEY_LEN);
    }
    else
    {
        mppe_set_keys(out + EAPTLS_MPPE_KEY_LEN, out, EAPTLS_MPPE_KEY_LEN);
    }
}

#endif /* MPPE */


void log_ssl_errors( void )
{
    unsigned long ssl_err = ERR_get_error();

    if (ssl_err != 0)
        dbglog("EAP-TLS SSL error stack:");
    while (ssl_err != 0) {
        dbglog( ERR_error_string( ssl_err, NULL ) );
        ssl_err = ERR_get_error();
    }
}


int password_callback (char *buf, int size, int rwflag, void *u)
{
    if (buf)
    {
        strlcpy (buf, passwd, size);
        return strlen (buf);
    }
    return 0;
}


CONF *eaptls_ssl_load_config( void )
{
    CONF        *config;
    int          ret_code;
    long         error_line = 33;

    config = NCONF_new( NULL );
    dbglog( "Loading OpenSSL config file" );
    ret_code = NCONF_load( config, _PATH_OPENSSLCONFFILE, &error_line );
    if (ret_code == 0)
    {
        warn( "EAP-TLS: Error in OpenSSL config file %s at line %d", _PATH_OPENSSLCONFFILE, error_line );
        NCONF_free( config );
        config = NULL;
        ERR_clear_error();
    }

    dbglog( "Loading OpenSSL built-ins" );
#ifndef OPENSSL_NO_ENGINE
    ENGINE_load_builtin_engines();
#endif
    OPENSSL_load_builtin_modules();
   
    dbglog( "Loading OpenSSL configured modules" );
    if (CONF_modules_load( config, NULL, 0 ) <= 0 )
    {
        warn( "EAP-TLS: Error loading OpenSSL modules" );
        log_ssl_errors();
        config = NULL;
    }

    return config;
}

#ifndef OPENSSL_NO_ENGINE
ENGINE *eaptls_ssl_load_engine( char *engine_name )
{
    ENGINE      *e = NULL;

    dbglog( "Enabling OpenSSL auto engines" );
    ENGINE_register_all_complete();

    dbglog( "Loading OpenSSL '%s' engine support", engine_name );
    e = ENGINE_by_id( engine_name );
    if (!e) 
    {
        dbglog( "EAP-TLS: Cannot load '%s' engine support, trying 'dynamic'", engine_name );
        e = ENGINE_by_id( "dynamic" );
        if (e)
        {
            if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine_name, 0)
             || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
            {
                warn( "EAP-TLS: Error loading dynamic engine '%s'", engine_name );
                log_ssl_errors();
                ENGINE_free(e);
                e = NULL;
            }
        }
        else
        {
            warn( "EAP-TLS: Cannot load dynamic engine support" );
        }
    }

    if (e)
    {
        dbglog( "Initialising engine" );
        if(!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            warn( "EAP-TLS: Cannot use that engine" );
            log_ssl_errors();
            ENGINE_free(e);
            e = NULL;
        }
    }

    return e;
}
#endif


#ifndef OPENSSL_NO_ENGINE
static int eaptls_UI_writer(UI *ui, UI_STRING *uis)
{
    PW_CB_DATA* cb_data = (PW_CB_DATA*)UI_get0_user_data(ui);
    UI_set_result(ui, uis, cb_data->password);
    return 1;
}

static int eaptls_UI_stub(UI* ui) {
    return 1;
}

static int eaptls_UI_reader(UI *ui, UI_STRING *uis) {
    return 1;
}
#endif

/*
 * Initialize the SSL stacks and tests if certificates, key and crl
 * for client or server use can be loaded.
 */
SSL_CTX *eaptls_init_ssl(int init_server, char *cacertfile, char *capath,
            char *certfile, char *peer_certfile, char *privkeyfile, char *pkcs12)
{
#ifndef OPENSSL_NO_ENGINE
    char        *cert_engine_name = NULL;
    char        *pkey_engine_name = NULL;
    char        *idx;
#endif
    SSL_CTX     *ctx;
    SSL         *ssl;
    X509_STORE  *certstore;
    X509_LOOKUP *lookup;
    X509        *tmp;
    X509        *cert = NULL;
    PKCS12      *p12 = NULL;
    EVP_PKEY    *pkey = NULL;
    STACK_OF(X509) *chain = NULL;
    BIO         *input;
    int          ret;
    int          reason;
#if defined(TLS1_2_VERSION)
    long         tls_version = TLS1_2_VERSION; 
#elif defined(TLS1_1_VERSION)
    long         tls_version = TLS1_1_VERSION; 
#else
    long         tls_version = TLS1_VERSION; 
#endif

    /*
     * Without these can't continue 
     */
    if (!pkcs12[0]) 
    {
        if (!(cacertfile[0] || capath[0]))
        {
            error("EAP-TLS: CA certificate file or path missing");
            return NULL;
        }

        if (!certfile[0])
        {
            error("EAP-TLS: Certificate missing");
            return NULL;
        }

        if (!privkeyfile[0])
        {
            error("EAP-TLS: Private key missing");
            return NULL;
        }
    }

    SSL_library_init();
    SSL_load_error_strings();

#ifndef OPENSSL_NO_ENGINE
    /* load the openssl config file only once and load it before triggering
       the loading of a global openssl config file via SSL_CTX_new()
     */
    if (!ssl_config)
        ssl_config = eaptls_ssl_load_config();
#endif

    ctx = SSL_CTX_new(TLS_method());

    if (!ctx) {
        error("EAP-TLS: Cannot initialize SSL CTX context");
        goto fail;
    }

#ifndef OPENSSL_NO_ENGINE
    /* if the certificate filename is of the form engine:id. e.g.
        pkcs11:12345
       then we try to load and use this engine.
       If the certificate filename starts with a / or . then we
       ALWAYS assume it is a file and not an engine/pkcs11 identifier
     */
    if ( (idx = index( certfile, ':' )) != NULL )
    {
        cert_engine_name = strdup( certfile );
        cert_engine_name[idx - certfile] = 0;

        dbglog( "Using engine '%s' for certificate, URI: '%s'",
                cert_engine_name, certfile );
    }

    /* if the privatekey filename is of the form engine:id. e.g.
        pkcs11:12345
       then we try to load and use this engine.
       If the privatekey filename starts with a / or . then we
       ALWAYS assume it is a file and not an engine/pkcs11 identifier
     */
    if ( (idx = index( privkeyfile, ':' )) != NULL )
    {
        pkey_engine_name = strdup( privkeyfile );
        pkey_engine_name[idx - privkeyfile] = 0;

        dbglog( "Using engine '%s' for private key, URI: '%s'",
                pkey_engine_name, privkeyfile );
    }

    if (cert_engine_name && pkey_engine_name)
    {
        if (strlen( certfile ) - strlen( cert_engine_name ) == 1)
        {
            if (strlen( privkeyfile ) - strlen( pkey_engine_name ) == 1)
                error( "EAP-TLS: both the certificate and privatekey identifiers are missing!" );
            else
            {
                dbglog( "Substituting privatekey identifier for certificate identifier" );
                certfile = privkeyfile;
            }
        }
        else
        {
            if (strlen( privkeyfile ) - strlen( pkey_engine_name ) == 1)
            {
                dbglog( "Substituting certificate identifier for privatekey identifier" );
                privkeyfile = certfile;
            }
        }
    }

    if (ssl_config && cert_engine_name)
        cert_engine = eaptls_ssl_load_engine( cert_engine_name );

    if (ssl_config && pkey_engine_name)
    {
        /* don't load the same engine twice */
        if ( cert_engine && strcmp( cert_engine_name, pkey_engine_name) == 0 )
            pkey_engine = cert_engine;
        else
            pkey_engine = eaptls_ssl_load_engine( pkey_engine_name );
    }

    if (cert_engine_name)
        free(cert_engine_name);

    if (pkey_engine_name)
        free(pkey_engine_name);

#endif

    SSL_CTX_set_default_passwd_cb (ctx, password_callback);

    if (strlen(cacertfile) == 0) cacertfile = NULL;
    if (strlen(capath) == 0)     capath = NULL;

    if (!SSL_CTX_load_verify_locations(ctx, cacertfile, capath))
    {
        error("EAP-TLS: Cannot load verify locations");
        if (cacertfile) dbglog("CA certificate file = [%s]", cacertfile);
        if (capath) dbglog("CA certificate path = [%s]", capath);
        goto fail;
    }

    if (init_server)
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(cacertfile));

#ifndef OPENSSL_NO_ENGINE
    if (cert_engine)
    {
        struct
        {
            const char *s_slot_cert_id;
            X509 *cert;
        } cert_info;

        cert_info.s_slot_cert_id = certfile;
        cert_info.cert = NULL;
        
        if (!ENGINE_ctrl_cmd( cert_engine, "LOAD_CERT_CTRL", 0, &cert_info, NULL, 0 ) )
        {
            error( "EAP-TLS: Error loading certificate with URI '%s' from engine", certfile );
            goto fail;
        }

        if (cert_info.cert)
        {
            dbglog( "Got the certificate" );
            dbglog( "subject = %s", X509_NAME_oneline( X509_get_subject_name( cert_info.cert ), NULL, 0 ) );
            cert = cert_info.cert;
        }
        else
        {
            warn("EAP-TLS: Cannot load key with URI: '%s'", certfile );
            log_ssl_errors();
        }
    }
    else
#endif
    {
        if (pkcs12[0])
        {
            input = BIO_new_file(pkcs12, "r");
            if (input == NULL)
            {
                error("EAP-TLS: Cannot open `%s' PKCS12 for input", pkcs12);
                goto fail;
            }

            p12 = d2i_PKCS12_bio(input, NULL);
            BIO_free(input);
            if (!p12)
            {
                error("EAP-TLS: Cannot load PKCS12 certificate");
                goto fail;
            }

            if (PKCS12_parse(p12, passwd, &pkey, &cert, &chain) != 1)
            {
                error("EAP-TLS: Cannot parse PKCS12 certificate, invalid password");
                PKCS12_free(p12);
                goto fail;
            }

            PKCS12_free(p12);
        }
        else 
        {
            if (!SSL_CTX_use_certificate_chain_file(ctx, certfile))
            {
                error( "EAP-TLS: Cannot load certificate %s", certfile );
                goto fail;
            }
        }
    }

    if (cert)
    {
        if (!SSL_CTX_use_certificate(ctx, cert))
        {
            error("EAP-TLS: Cannot use load certificate");
            goto fail;
        }

        if (chain)
        {
            int i;
            for (i = 0; i < sk_X509_num(chain); i++)
            {
                if (!SSL_CTX_add_extra_chain_cert(ctx, sk_X509_value(chain, i)))
                {
                    error("EAP-TLS: Cannot add extra chain certificate");
                    goto fail;
                }
            }
        }
    }

    /*
     *  Check the Before and After dates of the certificate
     */
    ssl = SSL_new(ctx);
    tmp = SSL_get_certificate(ssl);

    ret = X509_cmp_time(X509_get_notBefore(tmp), NULL);
    if (ret == 0)
    {    
        warn( "EAP-TLS: Failed to read certificate notBefore field.");
    }    
    if (ret > 0) 
    {    
        warn( "EAP-TLS: Your certificate is not yet valid!");
    }    

    ret = X509_cmp_time(X509_get_notAfter(tmp), NULL);
    if (ret == 0)
    {    
        warn( "EAP-TLS: Failed to read certificate notAfter field.");
    }    
    if (ret < 0)
    {
        warn( "EAP-TLS: Your certificate has expired!");
    }
    SSL_free(ssl);

#ifndef OPENSSL_NO_ENGINE
    if (pkey_engine)
    {
        PW_CB_DATA  cb_data;

        cb_data.password = passwd;
        cb_data.prompt_info = privkeyfile;

        if (passwd[0] != 0)
        {
            UI_METHOD* transfer_pin = UI_create_method("transfer_pin");

            UI_method_set_writer(transfer_pin,  eaptls_UI_writer);
            UI_method_set_opener(transfer_pin,  eaptls_UI_stub);
            UI_method_set_closer(transfer_pin,  eaptls_UI_stub);
            UI_method_set_flusher(transfer_pin, eaptls_UI_stub);
            UI_method_set_reader(transfer_pin,  eaptls_UI_reader);

            dbglog( "Using our private key URI: '%s' in engine", privkeyfile );
            pkey = ENGINE_load_private_key(pkey_engine, privkeyfile, transfer_pin, &cb_data);

            if (transfer_pin) UI_destroy_method(transfer_pin);
        }
        else {
            dbglog( "Loading private key URI: '%s' from engine", privkeyfile );
            pkey = ENGINE_load_private_key(pkey_engine, privkeyfile, NULL, NULL);
        }
    }
    else 
#endif
    {
        if (!pkey)
        {
            input = BIO_new_file(privkeyfile, "r");
            if (!input)
            {
                error("EAP-TLS: Could not open private key, %s", privkeyfile);
                goto fail;
            }

            pkey = PEM_read_bio_PrivateKey(input, NULL, password_callback, NULL);
            BIO_free(input);
            if (!pkey)
            {
                error("EAP-TLS: Cannot load private key, %s", privkeyfile);
                goto fail;
            }
        }
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    {
        error("EAP-TLS: Cannot use private key");
        goto fail;
    }

    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        error("EAP-TLS: Private key fails security check");
        goto fail;
    }

    /* Explicitly set the NO_TICKETS flag to support Win7/Win8 clients */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
#ifdef SSL_OP_NO_TICKET
    | SSL_OP_NO_TICKET
#endif
    );

    /* OpenSSL 1.1.1+ does not include RC4 ciphers by default.
     * This causes totally obsolete WinXP clients to fail. If you really
     * need ppp+EAP-TLS+openssl 1.1.1+WinXP then enable RC4 cipers and
     * make sure that you use an OpenSSL that supports them

    SSL_CTX_set_cipher_list(ctx, "RC4");
     */


    /* Set up a SSL Session cache with a callback. This is needed for TLSv1.3+.
     * During the initial handshake the server signals to the client early on
     * that the handshake is finished, even before the client has sent its
     * credentials to the server. The actual connection (and moment that the
     * client sends its credentials) only starts after the arrival of the first
     * session ticket. The 'ssl_new_session_cb' catches this ticket.
     */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(ctx, ssl_new_session_cb);

    /* As EAP-TLS+TLSv1.3 is highly experimental we offer the user a chance to override */
    if (max_tls_version)
    {
        if (strncmp(max_tls_version, "1.0", 3) == 0)
            tls_version = TLS1_VERSION;
        else if (strncmp(max_tls_version, "1.1", 3) == 0)
            tls_version = TLS1_1_VERSION;
        else if (strncmp(max_tls_version, "1.2", 3) == 0)
#ifdef TLS1_2_VERSION
            tls_version = TLS1_2_VERSION;
#else
        {
            warn("TLSv1.2 not available. Defaulting to TLSv1.1");
            tls_version = TLS_1_1_VERSION;
        }
#endif
        else if (strncmp(max_tls_version, "1.3", 3) == 0)
#ifdef TLS1_3_VERSION
            tls_version = TLS1_3_VERSION;
#else
            warn("TLSv1.3 not available.");
#endif
    }

    dbglog("EAP-TLS: Setting max protocol version to 0x%X", tls_version);
    SSL_CTX_set_max_proto_version(ctx, tls_version);

    SSL_CTX_set_verify_depth(ctx, 5);
    SSL_CTX_set_verify(ctx,
               SSL_VERIFY_PEER |
               SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
               &ssl_verify_callback);

    if (crl_dir) {
        if (!(certstore = SSL_CTX_get_cert_store(ctx))) {
            error("EAP-TLS: Failed to get certificate store");
            goto fail;
        }

        if (!(lookup =
             X509_STORE_add_lookup(certstore, X509_LOOKUP_hash_dir()))) {
            error("EAP-TLS: Store lookup for CRL failed");

            goto fail;
        }

        X509_LOOKUP_add_dir(lookup, crl_dir, X509_FILETYPE_PEM);
        X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);
    }

    if (crl_file) {
        FILE     *fp  = NULL;
        X509_CRL *crl = NULL;

        fp = fopen(crl_file, "r");
        if (!fp) {
            error("EAP-TLS: Cannot open CRL file '%s'", crl_file);
            goto fail;
        }

        crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
        if (!crl) {
            error("EAP-TLS: Cannot read CRL file '%s'", crl_file);
            goto fail;
        }

        if (!(certstore = SSL_CTX_get_cert_store(ctx))) {
            error("EAP-TLS: Failed to get certificate store");
            goto fail;
        }
        if (!X509_STORE_add_crl(certstore, crl)) {
            error("EAP-TLS: Cannot add CRL to certificate store");
            goto fail;
        }
        X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);

    }

    /*
     * If a peer certificate file was specified, it must be valid, else fail 
     */
    if (peer_certfile[0]) {
        if (!(tmp = get_X509_from_file(peer_certfile))) {
            error("EAP-TLS: Error loading client certificate from file %s",
                 peer_certfile);
            goto fail;
        }
        X509_free(tmp);
    }

    return ctx;

fail:

    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (chain)
        sk_X509_pop_free(chain, X509_free);

    log_ssl_errors();
    SSL_CTX_free(ctx);
    return NULL;
}

/*
 * Determine the maximum packet size by looking at the LCP handshake
 */

int eaptls_get_mtu(int unit)
{
    int mtu, mru;

    lcp_options *wo = &lcp_wantoptions[unit];
    lcp_options *go = &lcp_gotoptions[unit];
    lcp_options *ho = &lcp_hisoptions[unit];
    lcp_options *ao = &lcp_allowoptions[unit];

    mtu = ho->neg_mru? ho->mru: PPP_MRU;
    mru = go->neg_mru? MAX(wo->mru, go->mru): PPP_MRU;
    mtu = MIN(MIN(mtu, mru), ao->mru)- PPP_HDRLEN - 10;

    dbglog("MTU = %d", mtu);
    return mtu;
}


/*
 * Init the ssl handshake (server mode)
 */
int eaptls_init_ssl_server(eap_state * esp)
{
    struct eaptls_session *ets;
    char servcertfile[MAXWORDLEN];
    char clicertfile[MAXWORDLEN];
    char cacertfile[MAXWORDLEN];
    char capath[MAXWORDLEN];
    char pkfile[MAXWORDLEN];
    char pkcs12[MAXWORDLEN];

    /*
     * Allocate new eaptls session 
     */
    esp->es_server.ea_session = malloc(sizeof(struct eaptls_session));
    if (!esp->es_server.ea_session)
        fatal("Allocation error");
    ets = esp->es_server.ea_session;
    ets->client = 0;

    if (!esp->es_server.ea_peer) {
        error("EAP-TLS: Error: client name not set (BUG)");
        return 0;
    }

    strlcpy(ets->peer, esp->es_server.ea_peer, MAXWORDLEN-1);

    dbglog( "getting eaptls secret" );
    if (!get_eaptls_secret(esp->es_unit, esp->es_server.ea_peer,
                   esp->es_server.ea_name, clicertfile,
                   servcertfile, cacertfile, capath, pkfile, pkcs12, 1)) {
        error( "EAP-TLS: Cannot get secret/password for client \"%s\", server \"%s\"",
                esp->es_server.ea_peer, esp->es_server.ea_name );
        return 0;
    }

    ets->mtu = eaptls_get_mtu(esp->es_unit);

    ets->ctx = eaptls_init_ssl(1, cacertfile, capath, servcertfile, clicertfile, pkfile, pkcs12);
    if (!ets->ctx)
        goto fail;

    if (!(ets->ssl = SSL_new(ets->ctx)))
        goto fail;

    /*
     * Set auto-retry to avoid timeouts on BIO_read
     */
    SSL_set_mode(ets->ssl, SSL_MODE_AUTO_RETRY);

    /*
     * Initialize the BIOs we use to read/write to ssl engine 
     */
    ets->into_ssl = BIO_new(BIO_s_mem());
    ets->from_ssl = BIO_new(BIO_s_mem());
    SSL_set_bio(ets->ssl, ets->into_ssl, ets->from_ssl);

    SSL_set_msg_callback(ets->ssl, ssl_msg_callback);
    SSL_set_msg_callback_arg(ets->ssl, ets);

    /*
     * Attach the session struct to the connection, so we can later
     * retrieve it when doing certificate verification
     */
    SSL_set_ex_data(ets->ssl, 0, ets);

    SSL_set_accept_state(ets->ssl);

    ets->tls_v13 = 0;

    ets->data = NULL;
    ets->datalen = 0;
    ets->alert_sent = 0;
    ets->alert_recv = 0;

    /*
     * If we specified the client certificate file, store it in ets->peercertfile,
     * so we can check it later in ssl_verify_callback()
     */
    if (clicertfile[0])
        strlcpy(&ets->peercertfile[0], clicertfile, MAXWORDLEN);
    else
        ets->peercertfile[0] = 0;

    return 1;

fail:
    SSL_CTX_free(ets->ctx);
    return 0;
}

/*
 * Init the ssl handshake (client mode)
 */
int eaptls_init_ssl_client(eap_state * esp)
{
    struct eaptls_session *ets;
    char servcertfile[MAXWORDLEN];
    char clicertfile[MAXWORDLEN];
    char cacertfile[MAXWORDLEN];
    char capath[MAXWORDLEN];
    char pkfile[MAXWORDLEN];
    char pkcs12[MAXWORDLEN];

    /*
     * Allocate new eaptls session 
     */
    esp->es_client.ea_session = malloc(sizeof(struct eaptls_session));
    if (!esp->es_client.ea_session)
        fatal("Allocation error");
    ets = esp->es_client.ea_session;
    ets->client = 1;

    /*
     * If available, copy server name in ets; it will be used in cert
     * verify 
     */
    if (esp->es_client.ea_peer)
        strlcpy(ets->peer, esp->es_client.ea_peer, MAXWORDLEN-1);
    else
        ets->peer[0] = 0;
    
    ets->mtu = eaptls_get_mtu(esp->es_unit);

    dbglog( "calling get_eaptls_secret" );
    if (!get_eaptls_secret(esp->es_unit, esp->es_client.ea_name,
                   ets->peer, clicertfile,
                   servcertfile, cacertfile, capath, pkfile, pkcs12, 0)) {
        error( "EAP-TLS: Cannot get secret/password for client \"%s\", server \"%s\"",
                esp->es_client.ea_name, ets->peer );
        return 0;
    }

    dbglog( "calling eaptls_init_ssl" );
    ets->ctx = eaptls_init_ssl(0, cacertfile, capath, clicertfile, servcertfile, pkfile, pkcs12);
    if (!ets->ctx)
        goto fail;

    ets->ssl = SSL_new(ets->ctx);

    if (!ets->ssl)
        goto fail;

    /*
     * Initialize the BIOs we use to read/write to ssl engine 
     */
    dbglog( "Initializing SSL BIOs" );
    ets->into_ssl = BIO_new(BIO_s_mem());
    ets->from_ssl = BIO_new(BIO_s_mem());
    SSL_set_bio(ets->ssl, ets->into_ssl, ets->from_ssl);

    SSL_set_msg_callback(ets->ssl, ssl_msg_callback);
    SSL_set_msg_callback_arg(ets->ssl, ets);

    /*
     * Attach the session struct to the connection, so we can later
     * retrieve it when doing certificate verification
     */
    SSL_set_ex_data(ets->ssl, 0, ets);

    SSL_set_connect_state(ets->ssl);

    ets->tls_v13 = 0;

    ets->data = NULL;
    ets->datalen = 0;
    ets->alert_sent = 0;
    ets->alert_recv = 0;

    /*
     * If we specified the server certificate file, store it in
     * ets->peercertfile, so we can check it later in
     * ssl_verify_callback() 
     */
    if (servcertfile[0])
        strlcpy(ets->peercertfile, servcertfile, MAXWORDLEN);
    else
        ets->peercertfile[0] = 0;

    return 1;

fail:
    dbglog( "eaptls_init_ssl_client: fail" );
    SSL_CTX_free(ets->ctx);
    return 0;

}

void eaptls_free_session(struct eaptls_session *ets)
{
    if (ets->ssl)
        SSL_free(ets->ssl);

    if (ets->ctx)
        SSL_CTX_free(ets->ctx);

    free(ets);
}


int eaptls_is_init_finished(struct eaptls_session *ets)
{
    if (ets->ssl && SSL_is_init_finished(ets->ssl))
    {
        if (ets->tls_v13) 
            return have_session_ticket;
        else
            return 1;
    }

    return 0;
}

/*
 * Handle a received packet, reassembling fragmented messages and
 * passing them to the ssl engine
 */
int eaptls_receive(struct eaptls_session *ets, u_char * inp, int len)
{
    u_char flags;
    u_int tlslen = 0;
    u_char dummy[65536];

    if (len < 1) {
        warn("EAP-TLS: received no or invalid data");
        return 1;
    }
        
    GETCHAR(flags, inp);
    len--;

    if (flags & EAP_TLS_FLAGS_LI && len > 4) {
        /*
         * LenghtIncluded flag set -> this is the first packet of a message
        */

        /*
         * the first 4 octets are the length of the EAP-TLS message
         */
        GETLONG(tlslen, inp);
        len -= 4;

        if (!ets->data) {

            if (tlslen > EAP_TLS_MAX_LEN) {
                error("EAP-TLS: TLS message length > %d, truncated", EAP_TLS_MAX_LEN);
                tlslen = EAP_TLS_MAX_LEN;
            }

            /*
             * Allocate memory for the whole message
            */
            ets->data = malloc(tlslen);
            if (!ets->data)
                fatal("EAP-TLS: allocation error\n");

            ets->datalen = 0;
            ets->tlslen = tlslen;
        }
        else
            warn("EAP-TLS: non-first LI packet? that's odd...");
    }
    else if (!ets->data) {
        /*
         * A non fragmented message without LI flag
        */
 
        ets->data = malloc(len);
        if (!ets->data)
            fatal("EAP-TLS: memory allocation error in eaptls_receive\n");
 
        ets->datalen = 0;
        ets->tlslen = len;
    }

    if (flags & EAP_TLS_FLAGS_MF)
        ets->frag = 1;
    else
        ets->frag = 0;

    if (len < 0) {
        warn("EAP-TLS: received malformed data");
        return 1;
    }

    if (len + ets->datalen > ets->tlslen) {
        warn("EAP-TLS: received data > TLS message length");
        return 1;
    }

    BCOPY(inp, ets->data + ets->datalen, len);
    ets->datalen += len;

    if (!ets->frag) {

        /*
         * If we have the whole message, pass it to ssl 
         */

        if (ets->datalen != ets->tlslen) {
            warn("EAP-TLS: received data != TLS message length");
            return 1;
        }

        if (BIO_write(ets->into_ssl, ets->data, ets->datalen) == -1)
            log_ssl_errors();

        SSL_read(ets->ssl, dummy, 65536);

        free(ets->data);
        ets->data = NULL;
        ets->datalen = 0;
    }

    return 0;
}

/*
 * Return an eap-tls packet in outp.
 * A TLS message read from the ssl engine is buffered in ets->data.
 * At each call we control if there is buffered data and send a 
 * packet of mtu bytes.
 */
int eaptls_send(struct eaptls_session *ets, u_char ** outp)
{
    bool first = 0;
    int size;
    u_char fromtls[65536];
    int res;
    u_char *start;

    start = *outp;

    if (!ets->data)
    {
        if(!ets->alert_sent)
        {
            res = SSL_read(ets->ssl, fromtls, 65536);
        }

        /*
         * Read from ssl 
         */
        if ((res = BIO_read(ets->from_ssl, fromtls, 65536)) == -1)
        {
            warn("EAP-TLS send: No data from BIO_read");
            return 1;
        }

        ets->datalen = res;

        ets->data = malloc(ets->datalen);
        if (!ets->data)
            fatal("EAP-TLS: memory allocation error in eaptls_send\n");

        BCOPY(fromtls, ets->data, ets->datalen);

        ets->offset = 0;
        first = 1;
    }

    size = ets->datalen - ets->offset;
    
    if (size > ets->mtu) {
        size = ets->mtu;
        ets->frag = 1;
    } else
        ets->frag = 0;

    PUTCHAR(EAPT_TLS, *outp);

    /*
     * Set right flags and length if necessary 
     */
    if (ets->frag && first) {
        PUTCHAR(EAP_TLS_FLAGS_LI | EAP_TLS_FLAGS_MF, *outp);
        PUTLONG(ets->datalen, *outp);
    } else if (ets->frag) {
        PUTCHAR(EAP_TLS_FLAGS_MF, *outp);
    } else
        PUTCHAR(0, *outp);

    /*
     * Copy the data in outp 
     */
    BCOPY(ets->data + ets->offset, *outp, size);
    INCPTR(size, *outp);

    /*
     * Copy the packet in retransmission buffer 
     */
    BCOPY(start, &ets->rtx[0], *outp - start);
    ets->rtx_len = *outp - start;

    ets->offset += size;

    if (ets->offset >= ets->datalen) {

        /*
         * The whole message has been sent 
         */

        free(ets->data);
        ets->data = NULL;
        ets->datalen = 0;
        ets->offset = 0;
    }

    return 0;
}

/*
 * Get the sent packet from the retransmission buffer
 */
void eaptls_retransmit(struct eaptls_session *ets, u_char ** outp)
{
    BCOPY(ets->rtx, *outp, ets->rtx_len);
    INCPTR(ets->rtx_len, *outp);
}

/*
 * Verify a certificate.
 * Most of the work (signatures and issuer attributes checking)
 * is done by ssl; we check the CN in the peer certificate 
 * against the peer name.
 */
int ssl_verify_callback(int ok, X509_STORE_CTX * ctx)
{
    char subject[256];
    char cn_str[256];
    X509 *peer_cert;
    int err, depth;
    SSL *ssl;
    struct eaptls_session *ets;
    char *ptr1 = NULL, *ptr2 = NULL;

    peer_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    dbglog("certificate verify depth: %d", depth);

    if (auth_required && !ok) {
        X509_NAME_oneline(X509_get_subject_name(peer_cert),
                  subject, 256);

        X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
                      NID_commonName, cn_str, 256);

        dbglog("Certificate verification error:\n depth: %d CN: %s"
               "\n err: %d (%s)\n", depth, cn_str, err,
               X509_verify_cert_error_string(err));

        return 0;
    }

    ssl = X509_STORE_CTX_get_ex_data(ctx,
                       SSL_get_ex_data_X509_STORE_CTX_idx());

    ets = (struct eaptls_session *)SSL_get_ex_data(ssl, 0);

    if (ets == NULL) {
        error("Error: SSL_get_ex_data returned NULL");
        return 0;
    }

    log_ssl_errors();

    if (!depth) 
    {
        /* Verify certificate based on certificate type and extended key usage */
        if (tls_verify_key_usage) {
            int purpose = ets->client ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT ;
            if (X509_check_purpose(peer_cert, purpose, 0) == 0) {
                error("Certificate verification error: nsCertType mismatch");
                return 0;
            }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            int flags = ets->client ? XKU_SSL_SERVER : XKU_SSL_CLIENT;
            if (!(X509_get_extended_key_usage(peer_cert) & flags)) {
                error("Certificate verification error: invalid extended key usage");
                return 0;
            }
#endif
            info("Certificate key usage: OK");
        }

        /*
         * If acting as client and the name of the server wasn't specified
         * explicitely, we can't verify the server authenticity 
         */
        if (!tls_verify_method)
            tls_verify_method = TLS_VERIFY_NONE;

        if (!ets->peer[0] || !strcmp(TLS_VERIFY_NONE, tls_verify_method)) {
            warn("Certificate verication disabled or no peer name was specified");
            return ok;
        }

        /* This is the peer certificate */
        X509_NAME_oneline(X509_get_subject_name(peer_cert),
                  subject, 256);

        X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
                      NID_commonName, cn_str, 256);

        /* Verify based on subject name */
        ptr1 = ets->peer;
        if (!strcmp(TLS_VERIFY_SUBJECT, tls_verify_method)) {
            ptr2 = subject;
        }

        /* Verify based on common name (default) */
        if (strlen(tls_verify_method) == 0 ||
            !strcmp(TLS_VERIFY_NAME, tls_verify_method)) {
            ptr2 = cn_str;
        }

        /* Match the suffix of common name */
        if (!strcmp(TLS_VERIFY_SUFFIX, tls_verify_method)) {
            int len = strlen(ptr1);
            int off = strlen(cn_str) - len;
            ptr2 = cn_str;
            if (off > 0) {
                ptr2 = cn_str + off;
            }
        }

        if (strcmp(ptr1, ptr2)) {
            error("Certificate verification error: CN (%s) != %s", ptr1, ptr2);
            return 0;
        }

        info("Certificate CN: %s, peer name %s", cn_str, ets->peer);

        /*
         * If a peer certificate file was specified, here we check it 
         */
        if (ets->peercertfile[0]) {
            if (ssl_cmp_certs(&ets->peercertfile[0], peer_cert)
                != 0) {
                error
                    ("Peer certificate doesn't match stored certificate");
                return 0;
            }
        }
    }

    return ok;
}

/*
 * Compare a certificate with the one stored in a file
 */
int ssl_cmp_certs(char *filename, X509 * a)
{
    X509 *b;
    int ret;

    if (!(b = get_X509_from_file(filename)))
        return 1;

    ret = X509_cmp(a, b);
    X509_free(b);

    return ret;

}

X509 *get_X509_from_file(char *filename)
{
    FILE *fp;
    X509 *ret;

    if (!(fp = fopen(filename, "r")))
        return NULL;

    ret = PEM_read_X509(fp, NULL, NULL, NULL);

    fclose(fp);

    return ret;
}

/*
 * Every sent & received message this callback function is invoked,
 * so we know when alert messages have arrived or are sent and
 * we can print debug information about TLS handshake.
 */
void
ssl_msg_callback(int write_p, int version, int content_type,
         const void *buf, size_t len, SSL * ssl, void *arg)
{
    char string[256];
    struct eaptls_session *ets = (struct eaptls_session *)arg;
    unsigned char code;
    const unsigned char*msg = buf;
    int hvers = msg[1] << 8 | msg[2];

    if(write_p)
        strcpy(string, " -> ");
    else
        strcpy(string, " <- ");

    switch(content_type) {

    case SSL3_RT_HEADER:
        strcat(string, "SSL/TLS Header: ");
        switch(hvers) {
        case SSL3_VERSION:
                strcat(string, "SSL 3.0");
                break;
        case TLS1_VERSION:
                strcat(string, "TLS 1.0");
                break;
        case TLS1_1_VERSION:
                strcat(string, "TLS 1.1");
                break;
        case TLS1_2_VERSION:
                strcat(string, "TLS 1.2");
                break;
        default:
            sprintf(string, "SSL/TLS Header: Unknown version (%d)", hvers);
        }
        break;

    case SSL3_RT_ALERT:
        strcat(string, "Alert: ");
        code = msg[1];

        if (write_p) {
            ets->alert_sent = 1;
            ets->alert_sent_desc = code;
        } else {
            ets->alert_recv = 1;
            ets->alert_recv_desc = code;
        }

        strcat(string, SSL_alert_desc_string_long(code));
        break;

    case SSL3_RT_CHANGE_CIPHER_SPEC:
        strcat(string, "ChangeCipherSpec");
        break;

#ifdef SSL3_RT_INNER_CONTENT_TYPE
    case SSL3_RT_INNER_CONTENT_TYPE:
        strcat(string, "InnerContentType (TLS1.3)");
        break;
#endif

    case SSL3_RT_HANDSHAKE:

        strcat(string, "Handshake: ");
        code = msg[0];

        switch(code) {
            case SSL3_MT_HELLO_REQUEST:
                strcat(string,"Hello Request");
                break;
            case SSL3_MT_CLIENT_HELLO:
                strcat(string,"Client Hello");
                break;
            case SSL3_MT_SERVER_HELLO:
                strcat(string,"Server Hello");
                break;
#ifdef SSL3_MT_NEWSESSION_TICKET
            case SSL3_MT_NEWSESSION_TICKET:
                strcat(string,"New Session Ticket");
                break;
#endif
#ifdef SSL3_MT_END_OF_EARLY_DATA
            case SSL3_MT_END_OF_EARLY_DATA:
                strcat(string,"End of Early Data");
                break;
#endif
#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
            case SSL3_MT_ENCRYPTED_EXTENSIONS:
                strcat(string,"Encryped Extensions");
                break;
#endif
            case SSL3_MT_CERTIFICATE:
                strcat(string,"Certificate");
                break;
            case SSL3_MT_SERVER_KEY_EXCHANGE:
                strcat(string,"Server Key Exchange");
                break;
            case SSL3_MT_CERTIFICATE_REQUEST:
                strcat(string,"Certificate Request");
                break;
            case SSL3_MT_SERVER_DONE:
                strcat(string,"Server Hello Done");
                break;
            case SSL3_MT_CERTIFICATE_VERIFY:
                strcat(string,"Certificate Verify");
                break;
            case SSL3_MT_CLIENT_KEY_EXCHANGE:
                strcat(string,"Client Key Exchange");
                break;
            case SSL3_MT_FINISHED:
                strcat(string,"Finished: ");
                hvers = SSL_version(ssl);
                switch(hvers){
                    case SSL3_VERSION:
                        strcat(string, "SSL 3.0");
                        break;
                    case TLS1_VERSION:
                        strcat(string, "TLS 1.0");
                        break;
                    case TLS1_1_VERSION:
                        strcat(string, "TLS 1.1");
                        break;
                    case TLS1_2_VERSION:
                        strcat(string, "TLS 1.2");
                        break;
#ifdef TLS1_3_VERSION
                    case TLS1_3_VERSION:
                        strcat(string, "TLS 1.3 (experimental)");
                        ets->tls_v13 = 1;
                        break;
#endif
                    default:
                        strcat(string, "Unknown version");
                }
                break;
            default:
                sprintf( string, "Handshake: Unknown SSL3 code received: %d", code );
        }
        break;

    default:
        sprintf( string, "SSL message contains unknown content type: %d", content_type );
    }

    /* Alert messages must always be displayed */
    if(content_type == SSL3_RT_ALERT)
        error("%s", string);
    else
        dbglog("%s", string);
}

int 
ssl_new_session_cb(SSL *s, SSL_SESSION *sess)
{
    dbglog("EAP-TLS: Post-Handshake New Session Ticket arrived:");
    have_session_ticket = 1;

    /* always return success */
    return 1;
}

