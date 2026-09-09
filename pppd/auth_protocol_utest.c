/* SPDX-License-Identifier: BSD-3-Clause */
/* Run authentication state machines without a PPP device or a remote peer. */
#include "config.h"
#include "pppd-private.h"
#undef HAVE_CONFIG_H
#undef NDEBUG
#include <assert.h>
#include <string.h>

/* TLS transport is replaced below; authentication code runs unchanged. */
#undef PPP_WITH_EAPTLS
#undef PPP_WITH_MPPE
/* UNIT_TEST stubs logging in utils.c; here it would enable embedded test mains. */
#undef UNIT_TEST

/* Include the implementations to inspect state and invoke timer callbacks. */
#include "chap.c"
#include "chap-md5.c"
#ifdef PPP_WITH_CHAPMS
#include "chap_ms.c"
#endif
#include "eap.c"

#ifdef PPP_WITH_PEAP
#include <openssl/ssl.h>
static int test_SSL_read(SSL *ssl, void *buf, int len);
#define SSL_read test_SSL_read
#include "peap.c"
#undef SSL_read

char *max_tls_version, *ca_path, *cacert_file, *crl_dir, *crl_file;
int tls_init(void) { assert(0); return 0; }
const SSL_METHOD *tls_method(void) { assert(0); return NULL; }
int tls_set_opts(SSL_CTX *ctx) { assert(0); return 0; }
int tls_set_version(SSL_CTX *ctx, const char *version) { assert(0); return 0; }
int tls_set_verify(SSL_CTX *ctx, int depth) { assert(0); return 0; }
int tls_set_ca(SSL_CTX *ctx, const char *dir, const char *file) { assert(0); return 0; }
int tls_set_crl(SSL_CTX *ctx, const char *dir, const char *file) { assert(0); return 0; }
int tls_set_verify_info(SSL *ssl, const char *peer, const char *cert,
                        bool client, struct tls_info **out) { assert(0); return 0; }
void tls_free_verify_info(struct tls_info **info) { assert(0); }

static const u_char inner_request[22] = {
    EAPT_MSCHAPV2, CHAP_CHALLENGE, 7, 0, 21, 16
};
static int test_SSL_read(SSL *ssl, void *buf, int len)
{
    assert(len >= sizeof(inner_request));
    memcpy(buf, inner_request, sizeof(inner_request));
    return sizeof(inner_request);
}
#endif

int debug, error_count, unsuccess;
int peer_mru[NUM_PPP] = { PPP_MRU };
void novm(const char *msg) { assert(0); abort(); }
bool explicit_remote, session_mgmt;
char remote_name[MAXNAMELEN], devnam[1024];
u_char outpacket_buf[PPP_MRU + PPP_HDRLEN];
static int random_ok, random_calls, packets, peer_failures, client_failures;
static int timers, cancellations;
static u_char last_packet[PPP_MRU + PPP_HDRLEN];
static int last_length;

int auth_random_bytes(unsigned char *buf, int len)
{
    ++random_calls;
    memset(buf, random_ok ? 0xa5 : 0, len);
    return random_ok;
}

void output(int unit, unsigned char *pkt, int len)
{
    assert(len <= sizeof(last_packet));
    memcpy(last_packet, pkt, len);
    last_length = len;
    ++packets;
}
void auth_peer_fail(int unit, int protocol) { ++peer_failures; }
void auth_withpeer_fail(int unit, int protocol) { ++client_failures; }
void auth_peer_success(int unit, int protocol, int flavor, char *name, int len)
{ assert(0); }
void auth_withpeer_success(int unit, int protocol, int flavor) { assert(0); }
void ppp_timeout(ppp_timer_cb func, void *arg, int sec, int usec) { ++timers; }
void ppp_untimeout(void (*func)(void *), void *arg) { ++cancellations; }
void ppp_add_options(option_t *opts) {}
int get_secret(int unit, char *client_name, char *server_name, char *secret,
               int *len, int am_server)
{
    strcpy(secret, "clientPass");
    *len = strlen(secret);
    return 1;
}
int auth_number(void) { return 1; }
int session_start(const int flags, const char *user, const char *passwd,
                  const char *tty, char **msg) { return 1; }

static void reset(void)
{
    random_ok = 0;
    random_calls = packets = peer_failures = client_failures = 0;
    timers = cancellations = 0;
    last_length = 0;
    chap_lowerdown(0);
    chap_digests = NULL;
    chap_init(0);
    eap_init(0);
#ifdef PPP_WITH_CHAPMS
    chapms2_response_cache_size = chapms2_response_cache_next_index = 0;
#endif
    cancellations = 0;
}

static void test_chap_server(int digest)
{
    reset();
    chap_lowerup(0);
    chap_auth_peer(0, "server", digest);
    assert(random_calls == 1 && peer_failures == 1);
    assert(packets == 0 && timers == 0);
    assert((server.flags & (AUTH_FAILED | AUTH_DONE)) == (AUTH_FAILED | AUTH_DONE));
    assert(!(server.flags & (CHALLENGE_VALID | TIMEOUT_PENDING)));
    random_ok = 1;
    chap_server_timeout(&server);
    assert(random_calls == 1 && packets == 0 && peer_failures == 1);

    reset();
    random_ok = 1;
    chap_lowerup(0);
    chap_auth_peer(0, "server", digest);
    assert(packets == 1 && peer_failures == 0);
    assert(server.flags & CHALLENGE_VALID);
    assert(last_packet[PPP_HDRLEN] == CHAP_CHALLENGE);
    /* Retransmission reuses the challenge and must not request randomness. */
    random_ok = 0;
    chap_server_timeout(&server);
    assert(random_calls == 1 && packets == 2 && peer_failures == 0);
}

static void test_eap_server(enum eap_state_code state)
{
    eap_state *esp = &eap_states[0];
    reset();
    esp->es_server.ea_name = "server";
    esp->es_server.ea_namelen = 6;
    esp->es_server.ea_state = state;
    eap_send_request(esp);
    assert(random_calls == 1 && peer_failures == 1);
    assert(esp->es_server.ea_state == eapBadAuth);
    assert(esp->es_challen == 0 && timers == 0);
    /* EAP may send Failure, but never an authentication challenge. */
    assert(packets == 1 && last_length == PPP_HDRLEN + EAP_HEADERLEN);
    assert(last_packet[PPP_HDRLEN] == EAP_FAILURE);

    reset();
    random_ok = 1;
    esp->es_server.ea_name = "server";
    esp->es_server.ea_namelen = 6;
    esp->es_server.ea_state = state;
    eap_send_request(esp);
    assert(random_calls == 1 && packets == 1 && peer_failures == 0);
    assert(last_packet[PPP_HDRLEN] == EAP_REQUEST);
}

#ifdef PPP_WITH_CHAPMS
static void test_chap_client(void)
{
    u_char challenge[17] = { 16 };
    reset();
    chap_lowerup(0);
    chap_auth_with_peer(0, "User", CHAP_MICROSOFT_V2);
    timers = 0;
    chap_respond(&client, 7, challenge, sizeof(challenge));
    assert(random_calls == 1 && client_failures == 1 && packets == 0);
    assert(client.flags & AUTH_FAILED);
    assert(!(client.flags & TIMEOUT_PENDING));
    assert(chapms2_response_cache_size == 0);
    random_ok = 1;
    chap_respond(&client, 8, challenge, sizeof(challenge));
    assert(random_calls == 1 && packets == 0 && client_failures == 1);

    reset();
    random_ok = 1;
    chap_lowerup(0);
    chap_auth_with_peer(0, "User", CHAP_MICROSOFT_V2);
    chap_respond(&client, 7, challenge, sizeof(challenge));
    assert(packets == 1 && client_failures == 0);
    assert(last_packet[PPP_HDRLEN] == CHAP_RESPONSE);
    assert(chapms2_response_cache_size == 1);
    random_ok = 0;
    chap_respond(&client, 7, challenge, sizeof(challenge));
    assert(random_calls == 1 && packets == 2 && client_failures == 0);
}

static void test_eap_client(void)
{
    eap_state *esp = &eap_states[0];
    u_char request[22] = { EAPT_MSCHAPV2, CHAP_CHALLENGE, 7, 0, 21, 16 };
    reset();
    eap_authwithpeer(0, "User");
    timers = 0;
    eap_request(esp, request, 9, sizeof(request));
    assert(random_calls == 1 && client_failures == 1);
    assert(packets == 0 && timers == 0 && cancellations == 1);
    assert(esp->es_client.ea_state == eapBadAuth);
    assert(chapms2_response_cache_size == 0);

    reset();
    random_ok = 1;
    eap_authwithpeer(0, "User");
    eap_request(esp, request, 9, sizeof(request));
    assert(random_calls == 1 && client_failures == 0 && packets == 1);
    assert(last_packet[PPP_HDRLEN] == EAP_RESPONSE);
}
#endif

#ifdef PPP_WITH_PEAP
static void test_peap_client(void)
{
    eap_state *esp = &eap_states[0];
    u_char request[] = { EAPT_PEAP, 0 };
    u_char in_buf[TLS_RECORD_MAX_SIZE], out_buf[TLS_RECORD_MAX_SIZE];
    struct peap_state *psm;
    int i, out_len;

    /* A local failure must neither send a response nor negotiate a downgrade,
     * including when this was the first PEAP request.
     */
    for (i = 0; i < 2; ++i) {
        reset();
        eap_authwithpeer(0, "User");
        if (i) {
            esp->es_client.ea_state = eapAuthRecv;
            esp->es_client.ea_authtype = EAPT_PEAP;
        }
        psm = calloc(1, sizeof(*psm));
        assert(psm);
        psm->phase = PEAP_PHASE_2;
        psm->in_buf = in_buf;
        psm->out_buf = out_buf;
        psm->chap = chap_find_digest(CHAP_MICROSOFT_V2);
        esp->ea_peap = psm;
        timers = 0;
        eap_request(esp, request, 9, sizeof(request));
        assert(random_calls == 1 && client_failures == 1);
        assert(packets == 0 && timers == 0 && cancellations == 1);
        assert(esp->es_client.ea_state == eapBadAuth);
        assert(esp->ea_peap == NULL && chapms2_response_cache_size == 0);
    }

    reset();
    random_ok = 1;
    eap_authwithpeer(0, "User");
    psm = calloc(1, sizeof(*psm));
    assert(psm);
    psm->chap = chap_find_digest(CHAP_MICROSOFT_V2);
    psm->out_buf = out_buf;
    esp->ea_peap = psm;
    memcpy(in_buf, inner_request, sizeof(inner_request));
    out_len = sizeof(out_buf);
    peap_do_inner_eap(in_buf, sizeof(inner_request), esp, 9, out_buf, &out_len);
    assert(out_len > 0 && out_buf[0] == EAPT_MSCHAPV2 && out_buf[1] == CHAP_RESPONSE);
    assert(random_calls == 1 && chapms2_response_cache_size == 1);
    peap_finish(&esp->ea_peap);
}
#endif

int main(void)
{
    assert(PPP_crypto_init());
    test_chap_server(CHAP_MD5);
    test_eap_server(eapMD5Chall);
#ifdef PPP_WITH_CHAPMS
    test_chap_server(CHAP_MICROSOFT);
    test_chap_server(CHAP_MICROSOFT_V2);
    test_chap_client();
    test_eap_server(eapMSCHAPv2Chall);
    test_eap_client();
#endif
#ifdef PPP_WITH_PEAP
    test_peap_client();
#endif
    PPP_crypto_deinit();
    puts("Authentication protocol failure tests passed");
    return 0;
}
