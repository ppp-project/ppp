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

	int phase;
	int written, read;
	u_char *in_buf;
	u_char *out_buf;

	u_char ipmk[PEAP_TLV_IPMK_LEN];
	u_char tk[PEAP_TLV_TK_LEN];
	u_char nonce[PEAP_TLV_NONCE_LEN];
	struct tls_info *info;
#ifdef CHAPMS
	struct chap_digest_type *chap;
#endif
};

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

	max_iter = (pfr_len + SHA_DIGEST_LENGTH - 1) / SHA_DIGEST_LENGTH;
	buf = malloc(seed_len + max_iter * SHA_DIGEST_LENGTH);
	if (!buf)
		novm("pfr buffer");
	hash = malloc(pfr_len + SHA_DIGEST_LENGTH);
	if (!hash)
		novm("hash buffer");

	for (i = 0; i < max_iter; i++) {
		j = 0;
		k = 0;

		if (i > 0)
			j = SHA_DIGEST_LENGTH;
		for (k = 0; k < seed_len; k++)
			buf[j + k] = seed[k];
		pos = j + k;
		buf[pos] = i + 1;
		pos++;
		buf[pos] = 0x00;
		pos++;
		buf[pos] = 0x00;
		pos++;
		if (!HMAC(EVP_sha1(), key, key_len, buf, pos, (hash + i * SHA_DIGEST_LENGTH), &len))
			fatal("HMAC() failed");
		for (j = 0; j < SHA_DIGEST_LENGTH; j++)
			buf[j] = hash[i * SHA_DIGEST_LENGTH + j];
	}
	BCOPY(hash, out_buf, pfr_len);
	free(hash);
	free(buf);
}

static void generate_cmk(struct peap_state *psm, u_char *tempkey, u_char *nonce, u_char *tlv_response_out, int client)
{
	const char *label = PEAP_TLV_IPMK_SEED_LABEL;
	u_char data_tlv[PEAP_TLV_DATA_LEN] = {0};
	u_char isk[PEAP_TLV_ISK_LEN] = {0};
	u_char ipmkseed[PEAP_TLV_IPMKSEED_LEN] = {0};
	u_char cmk[PEAP_TLV_CMK_LEN] = {0};
	u_char buf[PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN] = {0};
	u_char compound_mac[PEAP_TLV_COMP_MAC_LEN] = {0};
	u_int len;

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

static void verify_compound_mac(struct peap_state *psm, u_char *in_buf)
{
	u_char nonce[PEAP_TLV_NONCE_LEN] = {0};
	u_char out_buf[PEAP_TLV_LEN] = {0};

	BCOPY(in_buf, nonce, PEAP_TLV_NONCE_LEN);
	generate_cmk(psm, psm->tk, nonce, out_buf, 0);
	if (memcmp((in_buf + PEAP_TLV_NONCE_LEN), (out_buf + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN), PEAP_TLV_CMK_LEN))
			fatal("server's CMK does not match client's CMK, potential MiTM");
}

#ifdef MPPE
#define PEAP_MPPE_KEY_LEN 32

static void generate_mppe_keys(struct peap_state *psm, int client)
{
	const char *label = PEAP_TLV_CSK_SEED_LABEL;
	u_char csk[PEAP_TLV_CSK_LEN] = {0};
	size_t len;

	dbglog("PEAP CB: generate mppe keys");
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
	struct peap_state *psm = esp->ea_peap;
	u_char *outp;
	int peap_len;

	outp = outpacket_buf;
	MAKEHEADER(outp, PPP_EAP);
	PUTCHAR(EAP_RESPONSE, outp);
	PUTCHAR(id, outp);
	esp->es_client.ea_id = id;

	if (psm->phase == PEAP_PHASE_1)
		peap_len = PEAP_HEADERLEN + PEAP_FRAGMENT_LENGTH_FIELD + len;
	else
		peap_len = PEAP_HEADERLEN + len;

	PUTSHORT(peap_len, outp);
	PUTCHAR(EAPT_PEAP, outp);

	if (psm->phase == PEAP_PHASE_1) {
		PUTCHAR(PEAP_L_FLAG_SET, outp);
		PUTLONG(len, outp);
	} else
		PUTCHAR(PEAP_NO_FLAGS, outp);

	BCOPY(buf, outp, len);
	output(esp->es_unit, outpacket_buf, PPP_HDRLEN + peap_len);
}

void peap_do_inner_eap(u_char *in_buf, int in_len, eap_state *esp, int id,
		u_char *out_buf, int *out_len)
{
	struct peap_state *psm = esp->ea_peap;
	int used = 0;
	int typenum;
	int secret_len;
	char secret[MAXSECRETLEN + 1];
	char rhostname[MAXWORDLEN];
	u_char *outp = out_buf;

	dbglog("PEAP: EAP (in): %.*B", in_len, in_buf);

	if (*(in_buf + EAP_HEADERLEN) == PEAP_CAPABILITIES_TYPE &&
			in_len  == (EAP_HEADERLEN + PEAP_CAPABILITIES_LEN)) {
		/* use original packet as template for response */
		BCOPY(in_buf, outp, EAP_HEADERLEN + PEAP_CAPABILITIES_LEN);
		PUTCHAR(EAP_RESPONSE, outp);
		PUTCHAR(id, outp);
		/* change last byte to 0 to disable fragmentation */
		*(outp + PEAP_CAPABILITIES_LEN + 1) = 0x00;
		used = EAP_HEADERLEN + PEAP_CAPABILITIES_LEN;
		goto done;
	}
	if (*(in_buf + EAP_HEADERLEN + PEAP_TLV_HEADERLEN) == PEAP_TLV_TYPE &&
			in_len == PEAP_TLV_LEN) {
		/* PEAP TLV message, do cryptobinding */
		SSL_export_keying_material(psm->ssl, psm->tk, PEAP_TLV_TK_LEN,
				PEAP_TLV_TK_SEED_LABEL, strlen(PEAP_TLV_TK_SEED_LABEL), NULL, 0, 0);
		/* verify server's CMK */
		verify_compound_mac(psm, in_buf + EAP_HEADERLEN + PEAP_TLV_RESULT_LEN + PEAP_TLV_HEADERLEN);
		/* generate client's CMK with new nonce */
		PUTCHAR(EAP_RESPONSE, outp);
		PUTCHAR(id, outp);
		PUTSHORT(PEAP_TLV_LEN, outp);
		BCOPY(in_buf + EAP_HEADERLEN, outp, PEAP_TLV_RESULT_LEN);
		outp = outp + PEAP_TLV_RESULT_LEN;
		RAND_bytes(psm->nonce, PEAP_TLV_NONCE_LEN);
		generate_cmk(psm, psm->tk, psm->nonce, outp, 1);
#ifdef MPPE
		/* set mppe keys */
		generate_mppe_keys(psm, 1);
#endif
		used = PEAP_TLV_LEN;
		goto done;
	}

	GETCHAR(typenum, in_buf);
	in_len--;

	switch (typenum) {
	case EAPT_IDENTITY:
		/* Respond with our identity to the peer */
		PUTCHAR(EAPT_IDENTITY, outp);
		BCOPY(esp->es_client.ea_name, outp,
				esp->es_client.ea_namelen);
		used += (esp->es_client.ea_namelen + 1);
		break;

	case EAPT_TLS:
		/* Send NAK to EAP_TLS request */
		PUTCHAR(EAPT_NAK, outp);
		PUTCHAR(EAPT_MSCHAPV2, outp);
		used += 2;
		break;

#if CHAPMS
	case EAPT_MSCHAPV2: {

		// Must have at least 4 more bytes to process CHAP header
		if (in_len < 4) {
			error("PEAP: received invalid MSCHAPv2 packet, too short");
			break;
		}

		u_char opcode;
		GETCHAR(opcode, in_buf);

		u_char chap_id;
		GETCHAR(chap_id, in_buf);

		short mssize;
		GETSHORT(mssize, in_buf);

		// Validate the CHAP packet (including header)
		if (in_len != mssize) {
			error("PEAP: received invalid MSCHAPv2 packet, invalid length");
			break;
		}
		in_len -= 4;

		switch (opcode) {
		case CHAP_CHALLENGE: {

			u_char *challenge = in_buf;	// VLEN + VALUE
			u_char vsize;

			GETCHAR(vsize, in_buf);
			in_len -= 1;

			if (vsize != MS_CHAP2_PEER_CHAL_LEN || in_len < MS_CHAP2_PEER_CHAL_LEN) {
				error("PEAP: received invalid MSCHAPv2 packet, invalid value-length: %d", vsize);
				goto done;
			}

			INCPTR(MS_CHAP2_PEER_CHAL_LEN, in_buf);
			in_len -= MS_CHAP2_PEER_CHAL_LEN;

			// Copy the provided remote host name
			rhostname[0] = '\0';
			if (in_len > 0) {
				if (in_len >= sizeof(rhostname)) {
					dbglog("PEAP: trimming really long peer name down");
					in_len = sizeof(rhostname) - 1;
				}
				BCOPY(in_buf, rhostname, in_len);
				rhostname[in_len] = '\0';
			}

			// In case the remote doesn't give us his name, or user explictly specified remotename is config
			if (explicit_remote || (remote_name[0] != '\0' && in_len == 0))
				strlcpy(rhostname, remote_name, sizeof(rhostname));

			// Get the scrert for authenticating ourselves with the specified host
			if (get_secret(esp->es_unit, esp->es_client.ea_name,
						rhostname, secret, &secret_len, 0)) {

				u_char response[MS_CHAP2_RESPONSE_LEN+1];
				u_char *user = esp->es_client.ea_name;
				u_char user_len = esp->es_client.ea_namelen;

				psm->chap->make_response(response, chap_id, user,
						challenge, secret, secret_len, NULL);

				PUTCHAR(EAPT_MSCHAPV2, outp);
				PUTCHAR(CHAP_RESPONSE, outp);
				PUTCHAR(chap_id, outp);
				PUTCHAR(0, outp);
				PUTCHAR(5 + user_len + MS_CHAP2_RESPONSE_LEN, outp);
				BCOPY(response, outp, MS_CHAP2_RESPONSE_LEN+1);	// VLEN + VALUE
				INCPTR(MS_CHAP2_RESPONSE_LEN+1, outp);
				BCOPY(user, outp, user_len);
				used = 5 + user_len + MS_CHAP2_RESPONSE_LEN + 1;

			} else {
				dbglog("PEAP: no CHAP secret for auth to %q", rhostname);
				PUTCHAR(EAPT_NAK, outp);
				++used;
			}
			break;
		}
		case CHAP_SUCCESS: {

			u_char status = CHAP_FAILURE;
			if (psm->chap->check_success(chap_id, in_buf, in_len)) {
				info("Chap authentication succeeded! %.*v", in_len, in_buf);
				status = CHAP_SUCCESS;
			}

			PUTCHAR(EAPT_MSCHAPV2, outp);
			PUTCHAR(status, outp);
			used += 2;
			break;
		}
		case CHAP_FAILURE: {

			psm->chap->handle_failure(in_buf, in_len);
			PUTCHAR(EAPT_MSCHAPV2, outp);
			PUTCHAR(status, outp);
			used += 2;
			break;
		}
		default:
			break;
		}
		break;
	}	// EAPT_MSCHAPv2
#endif
	default:

		/* send compressed EAP NAK for any unknown packet */
		PUTCHAR(EAPT_NAK, outp);
		++used;
	}

done:

	dbglog("PEAP: EAP (out): %.*B", used, psm->out_buf);
	*out_len = used;
}

int peap_init(struct peap_state **ctx, const char *rhostname)
{
	const SSL_METHOD *method;

	if (!ctx)
		return -1;

	tls_init();

	struct peap_state *psm = malloc(sizeof(*psm));
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

	/* Configure the max TLS version */
	tls_set_version(psm->ctx, max_tls_version);

	/* Configure the peer certificate callback */
	tls_set_verify(psm->ctx, 5);

	/* Configure CA locations */
	if (tls_set_ca(psm->ctx, ca_path, cacert_file)) {
		fatal("Could not set CA verify locations");
	}

	/* Configure CRL check (if any) */
	if (tls_set_crl(psm->ctx, crl_dir, crl_file)) {
		fatal("Could not set CRL verify locations");
	}

	psm->out_bio = BIO_new(BIO_s_mem());
	psm->in_bio = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(psm->out_bio, -1);
	BIO_set_mem_eof_return(psm->in_bio, -1);
	psm->ssl = SSL_new(psm->ctx);
	SSL_set_bio(psm->ssl, psm->in_bio, psm->out_bio);
	SSL_set_connect_state(psm->ssl);
	psm->phase = PEAP_PHASE_1;
	tls_set_verify_info(psm->ssl, explicit_remote ? rhostname : NULL, NULL, 1, &psm->info);
	psm->chap = chap_find_digest(CHAP_MICROSOFT_V2);
	*ctx = psm;
	return 0;
}

void peap_finish(struct peap_state **psm) {

	if (psm && *psm) {
		struct peap_state *tmp = *psm;

		if (tmp->ssl)
			SSL_free(tmp->ssl);

		if (tmp->ctx)
			SSL_CTX_free(tmp->ctx);

		if (tmp->info)
			tls_free_verify_info(&tmp->info);

		// NOTE: BIO and memory is freed as a part of SSL_free()

		free(*psm);
		*psm = NULL;
	}
}

int peap_process(eap_state *esp, u_char id, u_char *inp, int len)
{
	int ret;
	int out_len;

	struct peap_state *psm = esp->ea_peap;

	if (esp->es_client.ea_id == id) {
		info("PEAP: retransmits are not supported..");
		return -1;
	}

	switch (*inp) {
	case PEAP_S_FLAG_SET:
		dbglog("PEAP: S bit is set, starting PEAP phase 1");
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
		dbglog("PEAP TLS: LM bits are set, need to get more TLS fragments");
		inp = inp + PEAP_FRAGMENT_LENGTH_FIELD + PEAP_FLAGS_FIELD;
		psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FRAGMENT_LENGTH_FIELD - PEAP_FLAGS_FIELD);
		peap_ack(esp, id);
		break;

	case PEAP_M_FLAG_SET:
		dbglog("PEAP TLS: M bit is set, need to get more TLS fragments");
		inp = inp + PEAP_FLAGS_FIELD;
		psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FLAGS_FIELD);
		peap_ack(esp, id);
		break;

	case PEAP_L_FLAG_SET:
	case PEAP_NO_FLAGS:
		if (*inp == PEAP_L_FLAG_SET) {
			dbglog("PEAP TLS: L bit is set");
			inp = inp + PEAP_FRAGMENT_LENGTH_FIELD + PEAP_FLAGS_FIELD;
			psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FRAGMENT_LENGTH_FIELD - PEAP_FLAGS_FIELD);
		} else {
			dbglog("PEAP TLS: all bits are off");
			inp = inp + PEAP_FLAGS_FIELD;
			psm->written = BIO_write(psm->in_bio, inp, len - PEAP_FLAGS_FIELD);
		}

		if (psm->phase == PEAP_PHASE_1) {
			dbglog("PEAP TLS: continue handshake");
			ret = SSL_do_handshake(psm->ssl);
			if (ret != 1) {
				ret = SSL_get_error(psm->ssl, ret);
				if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE)
					fatal("SSL_do_handshake(): %s", ERR_error_string(ret, NULL));
			}
			if (SSL_is_init_finished(psm->ssl))
				psm->phase = PEAP_PHASE_2;
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
		peap_do_inner_eap(psm->in_buf, psm->read, esp, id,
				psm->out_buf, &out_len);
		if (out_len > 0) {
			psm->written = SSL_write(psm->ssl, psm->out_buf, out_len);
			psm->read = BIO_read(psm->out_bio, psm->out_buf,
				TLS_RECORD_MAX_SIZE);
			peap_response(esp, id, psm->out_buf, psm->read);
		}
		break;
	}
	return 0;
}
