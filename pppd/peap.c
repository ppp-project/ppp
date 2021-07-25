/*
 *      Copyright (c) 2011
 *
 * Authors:
 *
 *	Rustam Kovhaev <rkovhaev@gmail.com>
 *
 * PEAP has 2 phases,
 * 1 - Outer EAP, where TLS session gets established
 * 2 - Inner EAP, where inside TLS session with EAP MSCHAPV2 auth, or any
 * other auth
 *
 * And so protocols encapsulation looks like this:
 * Outer EAP -> TLS -> Inner EAP -> MSCHAPV2
 * PEAP can compress an inner EAP packet prior to encapsulating it within
 * the Data field of a PEAP packet by removing its Code, Identifier,
 * and Length fields, and Microsoft PEAP server/client always does that
 *
 * Current implementation does not support:
 * a) Fast reconnect
 * b) Inner EAP fragmentation
 * c) Any other auth other than MSCHAPV2
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "pppd.h"
#include "eap.h"
#include "tls.h"
#include "chap-new.h"
#include "chap_ms.h"
#include "mppe.h"
#include "peap.h"

struct peap_state {
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *in_bio;
	BIO *out_bio;

	int written, read;
	u_char *in_buf;
	u_char *out_buf;

	u_char ipmk[PEAP_TLV_IPMK_LEN];
	u_char tk[PEAP_TLV_TK_LEN];
	u_char nonce[PEAP_TLV_NONCE_LEN];
	struct tls_info *info;
};

static struct peap_state *psm;
static int peap_phase;
static bool init;

static void ssl_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
#endif
	init = 1;
}

/*
 * K = Key, S = Seed, LEN = output length
 * PRF+(K, S, LEN) = T1 | T2 | ... |Tn
 * Where:
 * T1 = HMAC-SHA1 (K, S | 0x01 | 0x00 | 0x00)
 * T2 = HMAC-SHA1 (K, T1 | S | 0x02 | 0x00 | 0x00)
 * ...
 * Tn = HMAC-SHA1 (K, Tn-1 | S | n | 0x00 | 0x00)
 * As shown, PRF+ is computed in iterations. The number of iterations (n)
 * depends on the output length (LEN).
 */
static void peap_prfplus(u_char *seed, size_t seed_len, u_char *key, size_t key_len, u_char *out_buf, size_t pfr_len)
{
	int pos;
	u_char *buf, *hash;
	size_t max_iter, i, j, k;
	u_int len;

	max_iter = (pfr_len + SHA_HASH_LEN - 1) / SHA_HASH_LEN;
	buf = malloc(seed_len + max_iter * SHA_HASH_LEN);
	if (!buf)
		novm("pfr buffer");
	hash = malloc(pfr_len + SHA_HASH_LEN);
	if (!hash)
		novm("hash buffer");

	for (i = 0; i < max_iter; i++) {
		j = 0;
		k = 0;

		if (i > 0)
			j = SHA_HASH_LEN;
		for (k = 0; k < seed_len; k++)
			buf[j + k] = seed[k];
		pos = j + k;
		buf[pos] = i + 1;
		pos++;
		buf[pos] = 0x00;
		pos++;
		buf[pos] = 0x00;
		pos++;
		if (!HMAC(EVP_sha1(), key, key_len, buf, pos, (hash + i * SHA_HASH_LEN), &len))
			fatal("HMAC() failed");
		for (j = 0; j < SHA_HASH_LEN; j++)
			buf[j] = hash[i * SHA_HASH_LEN + j];
	}
	BCOPY(hash, out_buf, pfr_len);
	free(hash);
	free(buf);
}

static void generate_cmk(u_char *tempkey, u_char *nonce, u_char *tlv_response_out, int client)
{
	const char *label = PEAP_TLV_IPMK_SEED_LABEL;
	u_char data_tlv[PEAP_TLV_DATA_LEN] = {0};
	u_char isk[PEAP_TLV_ISK_LEN] = {0};
	u_char ipmkseed[PEAP_TLV_IPMKSEED_LEN] = {0};
	u_char cmk[PEAP_TLV_CMK_LEN] = {0};
	u_char buf[PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN] = {0};
	u_char compound_mac[PEAP_TLV_COMP_MAC_LEN] = {0};
	u_int len;

	if (debug)
		info("PEAP CB: generate compound mac");
	/* format outgoing CB TLV response packet */
	data_tlv[1] = PEAP_TLV_TYPE;
	data_tlv[3] = PEAP_TLV_LENGTH_FIELD;
	if (client)
		data_tlv[7] = PEAP_TLV_SUBTYPE_RESPONSE;
	else
		data_tlv[7] = PEAP_TLV_SUBTYPE_REQUEST;
	BCOPY(nonce, (data_tlv + PEAP_TLV_HEADERLEN), PEAP_TLV_NONCE_LEN);
	data_tlv[60] = EAPT_PEAP;

#ifdef MPPE
    mppe_get_send_key(isk, MPPE_MAX_KEY_LEN);
    mppe_get_recv_key(isk + MPPE_MAX_KEY_LEN, MPPE_MAX_KEY_LEN);
#endif

	BCOPY(label, ipmkseed, strlen(label));
	BCOPY(isk, ipmkseed + strlen(label), PEAP_TLV_ISK_LEN);
	peap_prfplus(ipmkseed, PEAP_TLV_IPMKSEED_LEN,
			tempkey, PEAP_TLV_TEMPKEY_LEN, buf, PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN);

	BCOPY(buf, psm->ipmk, PEAP_TLV_IPMK_LEN);
	BCOPY(buf + PEAP_TLV_IPMK_LEN, cmk, PEAP_TLV_CMK_LEN);
	if (!HMAC(EVP_sha1(), cmk, PEAP_TLV_CMK_LEN, data_tlv, PEAP_TLV_DATA_LEN, compound_mac, &len))
		fatal("HMAC() failed");
	BCOPY(compound_mac, data_tlv + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN, PEAP_TLV_COMP_MAC_LEN);
	/* do not copy last byte to response packet */
	BCOPY(data_tlv, tlv_response_out, PEAP_TLV_DATA_LEN - 1);
}

static void verify_compound_mac(u_char *in_buf)
{
	u_char nonce[PEAP_TLV_NONCE_LEN] = {0};
	u_char out_buf[PEAP_TLV_LEN] = {0};

	BCOPY(in_buf, nonce, PEAP_TLV_NONCE_LEN);
	generate_cmk(psm->tk, nonce, out_buf, 0);
	if (memcmp((in_buf + PEAP_TLV_NONCE_LEN), (out_buf + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN), PEAP_TLV_CMK_LEN))
			fatal("server's CMK does not match client's CMK, potential MiTM");
}

#ifdef MPPE
#define PEAP_MPPE_KEY_LEN 32

static void generate_mppe_keys(int client)
{
	const char *label = PEAP_TLV_CSK_SEED_LABEL;
	u_char csk[PEAP_TLV_CSK_LEN] = {0};
	size_t len;

	if (debug)
		info("PEAP CB: generate mppe keys");
	len = strlen(label);
	len++; /* CSK requires NULL byte in seed */
	peap_prfplus((u_char *)label, len, psm->ipmk, PEAP_TLV_IPMK_LEN, csk, PEAP_TLV_CSK_LEN);

	/*
	 * The first 64 bytes of the CSK are split into two MPPE keys, as follows.
	 *
	 * +-----------------------+------------------------+
	 * | First 32 bytes of CSK | Second 32 bytes of CSK |
	 * +-----------------------+------------------------+
	 * | MS-MPPE-Send-Key      | MS-MPPE-Recv-Key       |
	 * +-----------------------+------------------------+
	 */
	if (client) {
		mppe_set_keys(csk, csk + PEAP_MPPE_KEY_LEN, PEAP_MPPE_KEY_LEN);
	} else {
		mppe_set_keys(csk + PEAP_MPPE_KEY_LEN, csk, PEAP_MPPE_KEY_LEN);
	}
}

#endif

static void dump(u_char *buf, int len)
{
	int i = 0;

	dbglog("len: %d bytes", len);
	for (i = 0; i < len; i++)
		printf("%02x ", buf[i]);
	printf("\n");
}

static void peap_ack(eap_state *esp, u_char id)
{
	u_char *outp;

	outp = outpacket_buf;
	MAKEHEADER(outp, PPP_EAP);
	PUTCHAR(EAP_RESPONSE, outp);
	PUTCHAR(id, outp);
	esp->es_client.ea_id = id;
	PUTSHORT(PEAP_HEADERLEN, outp);
	PUTCHAR(EAPT_PEAP, outp);
	PUTCHAR(PEAP_FLAGS_ACK, outp);
	output(esp->es_unit, outpacket_buf, PPP_HDRLEN + PEAP_HEADERLEN);
}

static void peap_response(eap_state *esp, u_char id, u_char *buf, int len)
{
	u_char *outp;
	int peap_len;

	outp = outpacket_buf;
	MAKEHEADER(outp, PPP_EAP);
	PUTCHAR(EAP_RESPONSE, outp);
	PUTCHAR(id, outp);
	esp->es_client.ea_id = id;

	if (peap_phase == PEAP_PHASE_1)
		peap_len = PEAP_HEADERLEN + PEAP_FRAGMENT_LENGTH_FIELD + len;
	else
		peap_len = PEAP_HEADERLEN + len;

	PUTSHORT(peap_len, outp);
	PUTCHAR(EAPT_PEAP, outp);

	if (peap_phase == PEAP_PHASE_1) {
		PUTCHAR(PEAP_L_FLAG_SET, outp);
		PUTLONG(len, outp);
	} else
		PUTCHAR(PEAP_NO_FLAGS, outp);

	BCOPY(buf, outp, len);
	output(esp->es_unit, outpacket_buf, PPP_HDRLEN + peap_len);
}

void do_inner_eap(u_char *in_buf, int in_len, eap_state *esp, int id,
		char *rhostname, u_char *out_buf, int *out_len)
{
	if (debug)
		dump(in_buf, in_len);
	int used;
	u_char *outp;

	used = 0;
	outp = out_buf;

	if (*in_buf == EAPT_IDENTITY && in_len == 1) {
		PUTCHAR(EAPT_IDENTITY, outp);
		used++;
		BCOPY(esp->es_client.ea_name, outp,
				esp->es_client.ea_namelen);
		used += esp->es_client.ea_namelen;
	} else if (*(in_buf + EAP_HEADERLEN) == PEAP_CAPABILITIES_TYPE &&
			in_len  == (EAP_HEADERLEN + PEAP_CAPABILITIES_LEN)) {
		/* use original packet as template for response */
		BCOPY(in_buf, outp, EAP_HEADERLEN + PEAP_CAPABILITIES_LEN);
		PUTCHAR(EAP_RESPONSE, outp);
		PUTCHAR(id, outp);
		/* change last byte to 0 to disable fragmentation */
		*(outp + PEAP_CAPABILITIES_LEN + 1) = 0x00;
		used = EAP_HEADERLEN + PEAP_CAPABILITIES_LEN;
	} else if (*in_buf == EAPT_TLS && in_len  == 2) {
		/* send NAK to EAP_TLS request */
		PUTCHAR(EAPT_NAK, outp);
		used++;
		PUTCHAR(EAPT_MSCHAPV2, outp);
		used++;
	} else if (*in_buf == EAPT_MSCHAPV2 && *(in_buf + 1) == CHAP_CHALLENGE) {
		/* MSCHAPV2 auth */
		int secret_len;
		char secret[MAXSECRETLEN + 1];
		char *user;
		u_char user_len;
		u_char response[MS_CHAP2_RESPONSE_LEN];
		u_char auth_response[MS_AUTH_RESPONSE_LENGTH + 1];
		u_char chap_id;
		u_char rchallenge[MS_CHAP2_PEER_CHAL_LEN];

		user = esp->es_client.ea_name;
		user_len = esp->es_client.ea_namelen;
		chap_id = *(in_buf + 2);
		BCOPY((in_buf + 6), rchallenge, MS_CHAP2_PEER_CHAL_LEN);
		if (!get_secret(esp->es_unit, esp->es_client.ea_name,
					rhostname, secret, &secret_len, 0))
			fatal("Can't read password file");
		/* MSCHAPV2 response */
		ChapMS2(rchallenge, NULL, esp->es_client.ea_name,
				secret, secret_len, response, auth_response, MS_CHAP2_AUTHENTICATEE);
		PUTCHAR(EAPT_MSCHAPV2, outp);
		PUTCHAR(CHAP_RESPONSE, outp);
		PUTCHAR(chap_id, outp);
		PUTCHAR(0, outp);
		PUTCHAR(5 + user_len + MS_CHAP2_RESPONSE_LEN, outp);
		PUTCHAR(MS_CHAP2_RESPONSE_LEN, outp)
		BCOPY(response, outp, MS_CHAP2_RESPONSE_LEN);
		outp = outp + MS_CHAP2_RESPONSE_LEN;
		BCOPY(user, outp, user_len);
		used = 5 + user_len + MS_CHAP2_RESPONSE_LEN + 1;
	} else if (*in_buf == EAPT_MSCHAPV2 && *(in_buf + 1) == CHAP_SUCCESS) {
		PUTCHAR(EAPT_MSCHAPV2, outp);
		used++;
		PUTCHAR(CHAP_SUCCESS, outp);
		used++;
		auth_peer_success(esp->es_unit, PPP_CHAP, CHAP_MICROSOFT_V2,
				esp->es_server.ea_peer, esp->es_server.ea_peerlen);
	} else if (*(in_buf + EAP_HEADERLEN + PEAP_TLV_HEADERLEN) == PEAP_TLV_TYPE &&
			in_len == PEAP_TLV_LEN) {
		/* PEAP TLV message, do cryptobinding */
		SSL_export_keying_material(psm->ssl, psm->tk, PEAP_TLV_TK_LEN,
				PEAP_TLV_TK_SEED_LABEL, strlen(PEAP_TLV_TK_SEED_LABEL), NULL, 0, 0);
		/* verify server's CMK */
		verify_compound_mac(in_buf + EAP_HEADERLEN + PEAP_TLV_RESULT_LEN + PEAP_TLV_HEADERLEN);
		/* generate client's CMK with new nonce */
		PUTCHAR(EAP_RESPONSE, outp);
		PUTCHAR(id, outp);
		PUTSHORT(PEAP_TLV_LEN, outp);
		BCOPY(in_buf + EAP_HEADERLEN, outp, PEAP_TLV_RESULT_LEN);
		outp = outp + PEAP_TLV_RESULT_LEN;
		RAND_bytes(psm->nonce, PEAP_TLV_NONCE_LEN);
		generate_cmk(psm->tk, psm->nonce, outp, 1);
#ifdef MPPE
		/* set mppe keys */
		generate_mppe_keys(1);
#endif
		used = PEAP_TLV_LEN;
	} else {
		/* send compressed EAP NAK for any unknown packet */
		PUTCHAR(EAPT_NAK, outp);
		++used;
	}

	if (debug)
		dump(psm->out_buf, used);
	*out_len = used;
}

void allocate_buffers(char *rhostname)
{
	const SSL_METHOD *method;

	psm = malloc(sizeof(*psm));
	if (!psm)
		novm("peap psm struct");
	psm->in_buf = malloc(TLS_RECORD_MAX_SIZE);
	if (!psm->in_buf)
		novm("peap tls buffer");
	psm->out_buf = malloc(TLS_RECORD_MAX_SIZE);
	if (!psm->out_buf)
		novm("peap tls buffer");
	method = tls_method();
	if (!method)
		novm("TLS_method() failed");
	psm->ctx = SSL_CTX_new(method);
	if (!psm->ctx)
		novm("SSL_CTX_new() failed");

	/* Configure the default options */
	tls_set_opts(psm->ctx);

	/* Configure CA locations */
	tls_set_ca(psm->ctx, ca_path, cacert_file);

	/* Configure CRL check (if any) */
	tls_set_crl(psm->ctx, crl_dir, crl_file);

	/* Configure the max TLS version */
	tls_set_version(psm->ctx, max_tls_version);

	/* Configure the peer certificate callback */
	tls_set_verify(psm->ctx, 5);

	psm->out_bio = BIO_new(BIO_s_mem());
	psm->in_bio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(psm->out_bio, -1);
	BIO_set_mem_eof_return(psm->in_bio, -1);
	psm->ssl = SSL_new(psm->ctx);
	SSL_set_bio(psm->ssl, psm->in_bio, psm->out_bio);
	SSL_set_connect_state(psm->ssl);
	peap_phase = PEAP_PHASE_1;
	tls_set_verify_info(psm->ssl, explicit_remote ? rhostname : NULL, NULL, 1, &psm->info);
}

void peap_process(eap_state *esp, u_char id, u_char *inp, int len, char *rhostname)
{
	int ret;
	int out_len;

	if (!init)
		ssl_init();

	if (esp->es_client.ea_id == id) {
		info("PEAP: retransmits are not supported..");
		return;
	}

	switch (*inp) {
	case PEAP_S_FLAG_SET:
		allocate_buffers(rhostname);
		if (debug)
			info("PEAP: S bit is set, starting PEAP phase 1");
		ret = SSL_do_handshake(psm->ssl);
		if (ret != 1) {
			ret = SSL_get_error(psm->ssl, ret);
			if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
				fatal("SSL_do_handshake(): %s", ERR_error_string(ret, NULL));

		}
		psm->read = BIO_read(psm->out_bio, psm->out_buf, TLS_RECORD_MAX_SIZE);
		peap_response(esp, id, psm->out_buf, psm->read);
		break;

	case PEAP_LM_FLAG_SET:
		if (debug)
			info("PEAP TLS: LM bits are set, need to get more TLS fragments");
		inp = inp + PEAP_FRAGMENT_LENGTH_FIELD + PEAP_FLAGS_FIELD;
		psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FRAGMENT_LENGTH_FIELD - PEAP_FLAGS_FIELD);
		peap_ack(esp, id);
		break;

	case PEAP_M_FLAG_SET:
		if (debug)
			info("PEAP TLS: M bit is set, need to get more TLS fragments");
		inp = inp + PEAP_FLAGS_FIELD;
		psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FLAGS_FIELD);
		peap_ack(esp, id);
		break;

	case PEAP_L_FLAG_SET:
	case PEAP_NO_FLAGS:
		if (*inp == PEAP_L_FLAG_SET) {
			if (debug)
				info("PEAP TLS: L bit is set");
			inp = inp + PEAP_FRAGMENT_LENGTH_FIELD + PEAP_FLAGS_FIELD;
			psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FRAGMENT_LENGTH_FIELD - PEAP_FLAGS_FIELD);
		} else {
			if (debug)
				info("PEAP TLS: all bits are off");
			inp = inp + PEAP_FLAGS_FIELD;
			psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FLAGS_FIELD);
		}

		if (peap_phase == PEAP_PHASE_1) {
			if (debug)
				info("PEAP TLS: continue handshake");
			ret = SSL_do_handshake(psm->ssl);
			if (ret != 1) {
				ret = SSL_get_error(psm->ssl, ret);
				if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
					fatal("SSL_do_handshake(): %s", ERR_error_string(ret, NULL));
			}
			if (SSL_is_init_finished(psm->ssl))
				peap_phase = PEAP_PHASE_2;
			if (BIO_ctrl_pending(psm->out_bio) == 0) {
				peap_ack(esp, id);
				break;
			}
			psm->read = 0;
			psm->read = BIO_read(psm->out_bio, psm->out_buf,
					TLS_RECORD_MAX_SIZE);
			peap_response(esp, id, psm->out_buf, psm->read);
			break;
		}
		psm->read = SSL_read(psm->ssl, psm->in_buf,
				TLS_RECORD_MAX_SIZE);
		out_len = TLS_RECORD_MAX_SIZE;
		do_inner_eap(psm->in_buf, psm->read, esp, id, rhostname,
				psm->out_buf, &out_len);
		psm->written = SSL_write(psm->ssl, psm->out_buf, out_len);
		psm->read = BIO_read(psm->out_bio, psm->out_buf,
				TLS_RECORD_MAX_SIZE);
		peap_response(esp, id, psm->out_buf, psm->read);
		break;
	}
}
