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
 */

#ifndef PPP_PEAP_H
#define	PPP_PEAP_H

/* TLV types */
#define TLV_RESULT_TYPE			0x8003
#define TLV_RESULT_LEN			2

#define TLV_CRYPTOBINDING_TYPE		0x000c
#define TLV_CRYPTOBINDING_LEN		56

/* Fields in cryptobinding TLV */
#define TLV_CB_SUBTYPE_OFF		7	/* offset of subtype byte */
#define TLV_CB_NONCE_OFF		8	/* offset of random nonce in CB TLV */
#define	TLV_CB_COMP_MAC_LEN		20	/* length of compound MAC in CB TLV */
#define TLV_CB_COMP_MAC_OFF		40	/* offset of above */
#define	TLV_CB_TLV_LEN			60	/* length of cryptobinding TLV structure */

/* Values for cryptobinding TLV subtype field */
#define TLV_CB_SUBTYPE_REQUEST		0
#define TLV_CB_SUBTYPE_RESPONSE		1

/**
 * Process a PEAP packet
 */
int peap_process(eap_state *esp, u_char id, u_char *inp, int len);

/* Receive an outer TLV */
void peap_receive_outer_tlv(eap_state *esp, int code, int id,
			    u_char *inp, int len);

/* Called when PEAP phase 2 starts */
void peap_phase2_start_server(eap_state *esp);
void peap_phase2_start_client(eap_state *esp);

/* Receive PEAP phase 2 decrypted data */
void peap_phase2_receive(eap_state *esp, int code, int id,
			 u_char *inp, int len);

/* Send PEAP phase 2 data to SSL */
void peap_phase2_send(eap_state *esp, int code, int id, u_char *data,
		      int datalen, bool compressed);

/* Send a capabilities method packet */
void peap_phase2_send_capabilities(eap_state *esp, int code, int id);

/* Send a success or failure Result TLV to the peer */
void peap_phase2_send_result(eap_state *esp, int code, int id, bool success);

#endif /* PPP_PEAP_H */
