/*
 * Copyright (c) 2011 Rustam Kovhaev. All rights reserved.
 * Copyright (c) 2021 Eivind Næss. All rights reserved.
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
 * NOTES:
 *
 * PEAP has 2 phases,
 * 1 - Outer EAP, where TLS session gets established
 * 2 - Inner EAP, where inside TLS session with EAP MSCHAPV2 auth, or any other auth
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
 * For details on the PEAP protocol, look to Microsoft:
 *    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-peap
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "pppd-private.h"
#include "eap.h"
#include "eap-tls.h"
#include "tls.h"
#include "chap.h"
#include "chap_ms.h"
#include "mppe.h"
#include "peap.h"
#include "fsm.h"

#ifdef UNIT_TEST
#define novm(x)
#endif

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
#ifdef PPP_WITH_CHAPMS
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

static void generate_cmk(u_char *ipmk, u_char *tempkey, u_char *nonce, u_char *tlv_response_out,
			 int client, int swap_isk)
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

#ifdef PPP_WITH_MPPE
	if (!swap_isk) {
		mppe_get_send_key(isk, MPPE_MAX_KEY_LEN);
		mppe_get_recv_key(isk + MPPE_MAX_KEY_LEN, MPPE_MAX_KEY_LEN);
	} else {
		mppe_get_recv_key(isk, MPPE_MAX_KEY_LEN);
		mppe_get_send_key(isk + MPPE_MAX_KEY_LEN, MPPE_MAX_KEY_LEN);
	}
#endif

	BCOPY(label, ipmkseed, strlen(label));
	BCOPY(isk, ipmkseed + strlen(label), PEAP_TLV_ISK_LEN);
	peap_prfplus(ipmkseed, PEAP_TLV_IPMKSEED_LEN,
			tempkey, PEAP_TLV_TEMPKEY_LEN, buf, PEAP_TLV_CMK_LEN + PEAP_TLV_IPMK_LEN);

	BCOPY(buf, ipmk, PEAP_TLV_IPMK_LEN);
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
	generate_cmk(psm->ipmk, psm->tk, nonce, out_buf, 0, 0);
	if (memcmp((in_buf + PEAP_TLV_NONCE_LEN), (out_buf + PEAP_TLV_HEADERLEN + PEAP_TLV_NONCE_LEN), PEAP_TLV_CMK_LEN))
			fatal("server's CMK does not match client's CMK, potential MiTM");
}

#ifdef PPP_WITH_MPPE
#define PEAP_MPPE_KEY_LEN 32

static void generate_mppe_keys(u_char *ipmk, int client)
{
	const char *label = PEAP_TLV_CSK_SEED_LABEL;
	u_char csk[PEAP_TLV_CSK_LEN] = {0};
	size_t len;

	dbglog("PEAP CB: generate mppe keys");
	len = strlen(label);
	len++; /* CSK requires NULL byte in seed */
	peap_prfplus((u_char *)label, len, ipmk, PEAP_TLV_IPMK_LEN, csk, PEAP_TLV_CSK_LEN);

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

#ifndef UNIT_TEST

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
	struct peap_state *psm = esp->es_client.ea_peap;
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

	/*
	 * XXX Dying here is better (just) than overflowing outpacket_buf[].
	 * There's not much point trying to continue, since the negotiation
	 * will stall at this point and never complete.
	 */
	if (peap_len > MIN(peer_mru[esp->es_unit], PPP_MRU))
		fatal("BUG! PEAP Response fragmentation not implemented!");

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
	struct peap_state *psm = esp->es_client.ea_peap;
	int used = 0;
	int typenum;
	int secret_len;
	char secret[MAXSECRETLEN + 1];
	char rhostname[MAXWORDLEN];
	u_char *outp = out_buf;

	dbglog("PEAP: EAP (in): %.*B", in_len, in_buf);

	if (in_len == (EAP_HEADERLEN + PEAP_CAPABILITIES_LEN) &&
	    *(in_buf + EAP_HEADERLEN) == PEAP_CAPABILITIES_TYPE) {
		/* use original packet as template for response */
		BCOPY(in_buf, outp, EAP_HEADERLEN + PEAP_CAPABILITIES_LEN);
		PUTCHAR(EAP_RESPONSE, outp);
		PUTCHAR(id, outp);
		/* change last byte to 0 to disable fragmentation */
		*(outp + PEAP_CAPABILITIES_LEN + 1) = 0x00;
		used = EAP_HEADERLEN + PEAP_CAPABILITIES_LEN;
		goto done;
	}
	if (in_len == PEAP_TLV_LEN &&
	    *(in_buf + EAP_HEADERLEN + PEAP_TLV_HEADERLEN) == PEAP_TLV_TYPE) {
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
		generate_cmk(psm->ipmk, psm->tk, psm->nonce, outp, 1, 0);
#ifdef PPP_WITH_MPPE
		/* set mppe keys */
		generate_mppe_keys(psm->ipmk, 1);
#endif
		used = PEAP_TLV_LEN;
		goto done;
	}

	if (in_len < 1) {
		dbglog("PEAP inner: dropping 0-length message");
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

#if PPP_WITH_CHAPMS
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

			if (in_len < 1) {
				error("PEAP inner: received empty CHAP_CHALLENGE");
				goto done;
			}
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
				u_char user_len = esp->es_client.ea_namelen;
				char *user = esp->es_client.ea_name;

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

			u_char status = CHAP_FAILURE;
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
	int hlen;
	int flags;

	struct peap_state *psm = esp->es_client.ea_peap;

	if (esp->es_client.ea_id == id) {
		info("PEAP: retransmits are not supported..");
		return -1;
	}
	if (len < 1) {
		error("PEAP received empty packet, discarding");
		return 0;
	}
	flags = *inp;
	dbglog("PEAP: flags=%c%c%c%c len=%d",
	       (flags & PEAP_L_FLAG_SET? 'L': '-'),
	       (flags & PEAP_M_FLAG_SET? 'M': '-'),
	       (flags & PEAP_S_FLAG_SET? 'S': '-'),
	       (flags & PEAP_T_FLAG_SET? 'T': '-'), len);
	hlen = 1;
	if (flags & PEAP_L_FLAG_SET) {
		hlen += PEAP_FRAGMENT_LENGTH_FIELD;
		if (len < hlen) {
			error("PEAP received short packet (%d bytes), discarding", len);
			return 0;
		}
	}
	inp += hlen;
	len -= hlen;

	if (flags & PEAP_S_FLAG_SET) {
		if (psm->phase == PEAP_PHASE_2) {
			warn("PEAP: Discarding spurious PEAP Start packet in phase 2");
			return 0;
		}
		dbglog("PEAP: starting PEAP phase 1");
		if (len > 0)
			warn("PEAP: Unexpected data in PEAP Start packet (%d bytes)", len);
	} else if (len > 0) {
		psm->written = BIO_write(psm->in_bio, inp, len);
	}

	if (flags & PEAP_M_FLAG_SET) {
		peap_ack(esp, id);
		return 0;
	}

	if (psm->phase == PEAP_PHASE_1) {
		if (!(flags & PEAP_S_FLAG_SET))
			dbglog("PEAP TLS: continue handshake");
		ret = SSL_do_handshake(psm->ssl);
		if (ret != 1) {
			ret = SSL_get_error(psm->ssl, ret);
			if (ret != SSL_ERROR_WANT_READ && ret != SSL_ERROR_WANT_WRITE) {
				error("SSL_do_handshake(): %s", ERR_error_string(ret, NULL));
				return -1;
			}
		}
		if (SSL_is_init_finished(psm->ssl))
			psm->phase = PEAP_PHASE_2;
		if (BIO_ctrl_pending(psm->out_bio) == 0) {
			peap_ack(esp, id);
			return 0;
		}
		psm->read = BIO_read(psm->out_bio, psm->out_buf,
				     TLS_RECORD_MAX_SIZE);
		if (psm->read <= 0) {
			error("PEAP: error reading TLS data to send (phase 1)");
			return 0;
		}
		peap_response(esp, id, psm->out_buf, psm->read);
	} else {
		psm->read = SSL_read(psm->ssl, psm->in_buf,
				TLS_RECORD_MAX_SIZE);
		if (psm->read <= 0) {
			error("PEAP: error reading tunneled data (phase 2)");
			return 0;
		}
		out_len = TLS_RECORD_MAX_SIZE;
		peap_do_inner_eap(psm->in_buf, psm->read, esp, id,
				psm->out_buf, &out_len);
		if (out_len > 0) {
			psm->written = SSL_write(psm->ssl, psm->out_buf, out_len);
			psm->read = BIO_read(psm->out_bio, psm->out_buf,
				TLS_RECORD_MAX_SIZE);
			if (psm->read <= 0) {
				error("PEAP: error reading TLS data to send (phase 2)");
				return 0;
			}
			peap_response(esp, id, psm->out_buf, psm->read);
		}
	}
	return 0;
}

/* Receive an outer TLV */
void peap_receive_outer_tlv(eap_state *esp, int code, int id, u_char *inp, int len)
{
}

eap_state peap_inner_eap;

bool cryptobinding_reqd = true;

/* Phase 2 is starting. code is from the outer PEAP packet. */
void peap_phase2_start_server(eap_state *esp)
{
	eap_state *eip = &peap_inner_eap;
	struct peap_state *psm;

	eip->outer_eap = esp;
	eip->es_server.ea_id = (u_char)(drand48() * 0x100);
	/* timeouts are left at zero; the outer PEAP makes a reliable transport */
#ifdef PPP_WITH_CHAPMS
	eip->es_client.digest = chap_find_digest(CHAP_MICROSOFT_V2);
	eip->es_server.digest = chap_find_digest(CHAP_MICROSOFT_V2);
#endif
	eip->es_server.ea_state = eapPending;
	eip->es_server.ea_session = esp->es_server.ea_session;
	eip->es_server.ea_name = esp->es_server.ea_name;
	eip->es_server.ea_namelen = esp->es_server.ea_namelen;

	/* Allocate a peap_state so we can use the crypto fields */
	esp->es_server.ea_peap = psm = malloc(sizeof(*psm));
	if (psm == NULL)
		novm("peap server psm struct");
	BZERO(psm, sizeof(*psm));

	eap_send_request(eip);
}

/* received EAP capabilities negotiation method */
static void peap_receive_cap_neg(eap_state *esp, int code, int id, u_char *inp, int len)
{
	dbglog("peap_receive_cap_neg");
}

/* receive EAP TLV extensions method packet */
static void peap_receive_tlv_ext(eap_state *esp, int code, int id, u_char *inp, int len)
{
	int ttype, tlen;
	int status = -1;
	int crypto_status = -1;
	u_char *next_tlv;
	eap_state *eop = esp->outer_eap;
	struct peap_state *psm = eop->es_server.ea_peap;
	u_char result_tlv[60];

	while (len >= 4) {
		GETSHORT(ttype, inp);
		GETSHORT(tlen, inp);
		len -= 4;
		if (len < tlen) {
			warn("PEAP: truncated TLV 0x%x (len=%d but only %dB left)",
			     ttype, tlen, len);
			break;
		}
		next_tlv = inp + tlen;
		len -= tlen;
		if (ttype == TLV_RESULT_TYPE && tlen == 2) {
			GETSHORT(status, inp);
			/* 1 = success, 2 = failure */
			if (status != 1 && status != 2)
				error("PEAP: bad status value %d in result TLV", status);
		} else if (ttype == TLV_CRYPTOBINDING_TYPE && tlen == 56) {
			/* check subtype */
			if (inp[3] != code - 1) {
				error("PEAP: cryptobinding TLV subtype doesn't match (%d)",
				      inp[3]);
			}
			INCPTR(4, inp);
			crypto_status = 1;
			/* psm->tk should be set already */
			/* inp is pointing to the client's nonce */
			generate_cmk(psm->ipmk, psm->tk, inp, result_tlv, 1, 1);
			if (memcmp(inp + PEAP_TLV_NONCE_LEN, result_tlv + 8 + PEAP_TLV_NONCE_LEN,
				   PEAP_TLV_COMP_MAC_LEN) != 0)
				crypto_status = 2;
		} else {
			warn("PEAP: TLV extensions method with unknown TLV 0x%x len %d",
			     ttype, tlen);
			if (ttype & 0x8000) {
				warn("PEAP: dropping packet with unknown mandatory TLV");
				return;
			}
		}
		inp = next_tlv;
	}
	if (len > 0)
		dbglog("leftover data at end of TLVs, %d bytes: %.*B", len, len, inp);

	if (crypto_status == 2 && !eop->es_server.ea_inner_fail) {
		if (cryptobinding_reqd) {
			error("PEAP: Cryptobinding failure");
			status = 2;
		} else {
			warn("PEAP: Cryptobinding failure");
		}
	}
	if (status < 0) {
		warn("PEAP: TLV extensions method with no Result TLV, ignored");
		return;
	}

	eop->es_server.ea_inner_done = true;
	if (status != 1)
		eop->es_server.ea_inner_fail = true;
	else if (crypto_status < 0)
		/* should this be an error? */
		info("PEAP: No cryptobinding performed");
	dbglog("PEAP: Inner EAP %s", (status == 1? "success": "failure"));
#ifdef PPP_WITH_MPPE
	if (crypto_status == 1)
		generate_mppe_keys(psm->ipmk, 0); /* set mppe keys */
#endif
	esp->es_server.ea_state = eop->es_server.ea_inner_fail? eapBadAuth: eapOpen;
}

/*
 * Receive PEAP phase 2 decrypted data.
 * code and id are from the outer PEAP packet.
 * inp[0..len-1] is the decrypted inner packet.
 */
void peap_phase2_receive(eap_state *esp, int code, int id, u_char *inp, int len)
{
	eap_state *eip = &peap_inner_eap;
	int type;
	int iid, ilen, itype, ivend, ivtype;
	u_char *p;
	static u_char dbuf[1504];
	u_char *outp = dbuf;

	if (!eap_server_active(eip)) {
		warn("PEAP/inner: dropping packet when not active (state=%d)",
		     eip->es_server.ea_state);
		return;
	}

	if (len < 1) {
		dbglog("PEAP/inner: dropping short packet (len=%d)", len);
		return;
	}
	type = *inp;

	/*
	 * The EAP packet could be "compressed", meaning that
	 * its EAP code, id and len fields are omitted.
	 * Only EAP TLV Extensions method (type = 33), capabilities
	 * negotiation method (type = 254, vendor/vtype = 311/34) and
	 * SoH EAP Extensions method (type = 254, vendor/vtype = 311/33)
	 * packets are NOT compressed (and they are never compressed).
	 */
	if (len >= 9 && type == code) {
		p = inp + 1;
		GETCHAR(iid, p);
		GETSHORT(ilen, p);
		GETCHAR(itype, p);
		if (ilen <= len && itype == EAPT_EXPANDED && len >= 16 &&
		    p[0] == 0 && p[1] == 1 && p[2] == 0x37) {
			/* expanded type, vendor microsoft, uncompressed */
			INCPTR(3, p);
			GETLONG(ivtype, p);
			switch (ivtype) {
			case 34:
				peap_receive_cap_neg(eip, code, iid, p, ilen - 5);
				break;
			default:
				error("PEAP phase 2 received unknown MS vendor method 0x%x",
				      ivtype);
			}
			return;
		} else if (ilen <= len && itype == EAPT_TLV_EXT) {
			/* EAP TLV extensions method, uncompressed */
			if (eip->es_server.ea_state != eapPeap2SentResult) {
				warn("PEAP phase 2 dropping unexpected TLV extensions packet");
				return;
			}
			peap_receive_tlv_ext(eip, code, iid, p, ilen - 5);
			return;
		}
	}

	/* Packet is a compressed EAP packet here */
	if (debug) {
		/* make a PPP header and an EAP header so we can print it */
		MAKEHEADER(outp, PPP_EAP);
		PUTCHAR(code, outp);
		PUTCHAR(id, outp);
		PUTSHORT(len + EAP_HEADERLEN, outp);
		if (len > 0)
			BCOPY(inp, outp, len);
		dump_packet("inner recv", dbuf, len + EAP_HEADERLEN + PPP_HDRLEN);
	}

	switch(code) {
	case EAP_RESPONSE:
		peap_inner_response(eip, id, inp, len);
		break;
	default:
		error("PEAP/inner: received unknown code %d, ignoring", code);
	}
}

/*
 * Send PEAP phase 2 data to SSL.
 * This is usually data from the generic EAP implementation,
 * which always gets "compressed" by leaving off the EAP header,
 * but can also be PEAP-specific packets which are not compressed.
 */
void peap_phase2_send(eap_state *esp, int code, int id, u_char *data, int datalen, bool compressed)
{
	struct eaptls_session *ets = esp->es_server.ea_session;
	int res;
	size_t written;
	static u_char dbuf[1504];
	u_char *outp = dbuf;
	int hlen;

	if (debug) {
		hlen = PPP_HDRLEN;
		MAKEHEADER(outp, PPP_EAP);
		if (compressed) {
			PUTCHAR(code, outp);
			PUTCHAR(id, outp);
			PUTSHORT(datalen + EAP_HEADERLEN, outp);
			hlen += EAP_HEADERLEN;
		}
		if (datalen > 0)
			BCOPY(data, outp, datalen);
		dump_packet("inner sent", dbuf, hlen + datalen);
	}

	if (datalen <= 0) {
		error("PEAP/inner: can't send zero-length packet");
		return;
	}
	written = SSL_write(ets->ssl, data, datalen);
	if (written <= 0) {
		res = SSL_get_error(ets->ssl, 0);
		if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE)
			error("PEAP-server failed to write all data (len=%d)", datalen);
		else
			error("PEAP-server write error: %s", ERR_error_string(res, NULL));
	}
}

/*
 * Send a Result TLV to the peer in a EAP-TLV-Extensions method packet
 * We also send a Crypto-binding TLV on success.
 */
void peap_phase2_send_result(eap_state *esp, int code, bool success)
{
	u_char *outp, *lenp;
	int id, len;
	eap_state *eop = esp->outer_eap;
	struct peap_state *psm = eop->es_server.ea_peap;
	struct eaptls_session *ets = eop->es_server.ea_session;

	outp = outpacket_buf;

	/* TLV Extensions method is never compressed */
	esp->es_server.ea_id = id = (esp->outer_eap->es_server.ea_id + 1) & 0xff;
	PUTCHAR(code, outp);
	PUTCHAR(id, outp);
	lenp = outp;
	INCPTR(2, outp);
	PUTCHAR(EAPT_TLV_EXT, outp);

	/* Result TLV */
	PUTSHORT(TLV_RESULT_TYPE, outp);
	PUTSHORT(2, outp);	/* value length */
	PUTSHORT(success? 1: 2, outp);

	if (success) {
		/* Cryptobinding TLV */
		SSL_export_keying_material(ets->ssl, psm->tk, PEAP_TLV_TK_LEN,
				PEAP_TLV_TK_SEED_LABEL, strlen(PEAP_TLV_TK_SEED_LABEL),
				NULL, 0, 0);
		/* create nonce */
		RAND_bytes(psm->nonce, PEAP_TLV_NONCE_LEN);
		generate_cmk(psm->ipmk, psm->tk, psm->nonce, outp, 0, 1);
		INCPTR(60, outp);
	} else
		eop->es_server.ea_inner_fail = true;

	/* Fill in length */
	len = outp - outpacket_buf;
	PUTSHORT(len, lenp);

	esp->es_server.ea_state = eapPeap2SentResult;

	peap_phase2_send(esp, code, id, outpacket_buf, len, false);
}

#else

u_char outpacket_buf[255];
int debug = 1;
int error_count = 0;
int unsuccess = 0;

/**
 * Using the example in MS-PEAP, section 4.4.1.
 *	see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-peap/5308642b-90c9-4cc4-beec-fb367325c0f9
 */
int test_cmk(u_char *ipmk) {
	u_char nonce[PEAP_TLV_NONCE_LEN] = {
		0x6C, 0x6B, 0xA3, 0x87, 0x84, 0x23, 0x74, 0x57,
		0xCC, 0xC9, 0x0B, 0x1A, 0x90, 0x8C, 0xBD, 0xF4,
		0x71, 0x1B, 0x69, 0x99, 0x4D, 0x0C, 0xFE, 0x8D,
		0x3D, 0xB4, 0x4E, 0xCB, 0xCD, 0xAD, 0x37, 0xE9
	};

	u_char tmpkey[PEAP_TLV_TEMPKEY_LEN] = {
		0x73, 0x8B, 0xB5, 0xF4, 0x62, 0xD5, 0x8E, 0x7E,
		0xD8, 0x44, 0xE1, 0xF0, 0x0D, 0x0E, 0xBE, 0x50,
		0xC5, 0x0A, 0x20, 0x50, 0xDE, 0x11, 0x99, 0x77,
		0x10, 0xD6, 0x5F, 0x45, 0xFB, 0x5F, 0xBA, 0xB7,
		0xE3, 0x18, 0x1E, 0x92, 0x4F, 0x42, 0x97, 0x38,
		// 0xDE, 0x40, 0xC8, 0x46, 0xCD, 0xF5, 0x0B, 0xCB,
		// 0xF9, 0xCE, 0xDB, 0x1E, 0x85, 0x1D, 0x22, 0x52,
		// 0x45, 0x3B, 0xDF, 0x63
	};

	u_char expected[60] = {
		0x00, 0x0C, 0x00, 0x38, 0x00, 0x00, 0x00, 0x01,
		0x6C, 0x6B, 0xA3, 0x87, 0x84, 0x23, 0x74, 0x57,
		0xCC, 0xC9, 0x0B, 0x1A, 0x90, 0x8C, 0xBD, 0xF4,
		0x71, 0x1B, 0x69, 0x99, 0x4D, 0x0C, 0xFE, 0x8D,
		0x3D, 0xB4, 0x4E, 0xCB, 0xCD, 0xAD, 0x37, 0xE9,
		0x42, 0xE0, 0x86, 0x07, 0x1D, 0x1C, 0x8B, 0x8C,
		0x8E, 0x45, 0x8F, 0x70, 0x21, 0xF0, 0x6A, 0x6E,
		0xAB, 0x16, 0xB6, 0x46
	};

	u_char inner_mppe_keys[32] = {
		0x67, 0x3E, 0x96, 0x14, 0x01, 0xBE, 0xFB, 0xA5,
		0x60, 0x71, 0x7B, 0x3B, 0x5D, 0xDD, 0x40, 0x38,
		0x65, 0x67, 0xF9, 0xF4, 0x16, 0xFD, 0x3E, 0x9D,
		0xFC, 0x71, 0x16, 0x3B, 0xDF, 0xF2, 0xFA, 0x95
	};

	u_char response[60] = {};

	// Set the inner MPPE keys (e.g. from CHAPv2)
	mppe_set_keys(inner_mppe_keys, inner_mppe_keys + 16, 16);

	// Generate and compare the response
	generate_cmk(ipmk, tmpkey, nonce, response, 1, 0);
	if (memcmp(expected, response, sizeof(response)) != 0) {
		dbglog("Failed CMK key generation\n");
		dbglog("%.*B", sizeof(response), response);
		dbglog("%.*B", sizeof(expected), expected);
		return -1;
	}

	return 0;
}

int test_mppe(u_char *ipmk) {
	u_char outer_mppe_send_key[MPPE_MAX_KEY_SIZE] = {
		0x6A, 0x02, 0xD7, 0x82, 0x20, 0x1B, 0xC7, 0x13,
		0x8B, 0xF8, 0xEF, 0xF7, 0x33, 0xB4, 0x96, 0x97,
		0x0D, 0x7C, 0xAB, 0x30, 0x0A, 0xC9, 0x57, 0x72,
		0x78, 0xE1, 0xDD, 0xD5, 0xAE, 0xF7, 0x66, 0x97
	};

	u_char outer_mppe_recv_key[MPPE_MAX_KEY_SIZE] = {
		0x17, 0x52, 0xD4, 0xE5, 0x84, 0xA1, 0xC8, 0x95,
		0x03, 0x9B, 0x4D, 0x05, 0xE3, 0xBC, 0x9A, 0x84,
		0x84, 0xDD, 0xC2, 0xAA, 0x6E, 0x2C, 0xE1, 0x62,
		0x76, 0x5C, 0x40, 0x68, 0xBF, 0xF6, 0x5A, 0x45
	};

	u_char result[MPPE_MAX_KEY_SIZE];
	int len;

	mppe_clear_keys();

	generate_mppe_keys(ipmk, 1);

	len = mppe_get_recv_key(result, sizeof(result));
	if (len != sizeof(result)) {
		dbglog("Invalid length of resulting MPPE recv key");
		return -1;
	}

	if (memcmp(result, outer_mppe_recv_key, len) != 0) {
		dbglog("Invalid result for outer mppe recv key");
		return -1;
	}

	len = mppe_get_send_key(result, sizeof(result));
	if (len != sizeof(result)) {
		dbglog("Invalid length of resulting MPPE send key");
		return -1;
	}

	if (memcmp(result, outer_mppe_send_key, len) != 0) {
		dbglog("Invalid result for outer mppe send key");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	 u_char ipmk[PEAP_TLV_IPMK_LEN] = {
		0x3A, 0x91, 0x1C, 0x25, 0x54, 0x73, 0xE8, 0x3E,
		0x9A, 0x0C, 0xC3, 0x33, 0xAE, 0x1F, 0x8A, 0x35,
		0xCD, 0xC7, 0x41, 0x63, 0xE7, 0xF6, 0x0F, 0x6C,
		0x65, 0xEF, 0x71, 0xC2, 0x64, 0x42, 0xAA, 0xAC,
		0xA2, 0xB6, 0xF1, 0xEB, 0x4F, 0x25, 0xEC, 0xA3,
	};
	int ret = -1;

	ret = test_cmk(ipmk);
	if (ret != 0) {
		return -1;
	}

	ret = test_mppe(ipmk);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

#endif
