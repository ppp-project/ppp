/*
 *      Copyright (c) 2011
 *
 * Authors:
 *
 *	Rustam Kovhaev <rkovhaev@gmail.com>
 */

#ifndef PPP_PEAP_H
#define	PPP_PEAP_H

#define	EAPT_MSCHAPV2			26

#define	PEAP_PHASE_1			1
#define	PEAP_PHASE_2			2

#define	PEAP_HEADERLEN			6
#define	PEAP_FRAGMENT_LENGTH_FIELD	4
#define	PEAP_FLAGS_FIELD		1
#define	PEAP_FLAGS_ACK			0

#define PEAP_CAPABILITIES_TYPE		254
#define PEAP_CAPABILITIES_LEN		12

#define	SHA_HASH_LEN			20

#define PEAP_TLV_TYPE			12
#define PEAP_TLV_LENGTH_FIELD		56
#define PEAP_TLV_SUBTYPE_REQUEST	0
#define PEAP_TLV_SUBTYPE_RESPONSE	1
#define PEAP_TLV_HEADERLEN		8
#define PEAP_TLV_RESULT_LEN		7
#define PEAP_TLV_LEN			71

/*
 * Microsoft PEAP client/server never exchange
 * outer TLVs during PEAP authentication
 */
#define	PEAP_TLV_DATA_LEN		61

#define	PEAP_TLV_TK_LEN			60
#define	PEAP_TLV_ISK_LEN		32
#define	PEAP_TLV_IPMKSEED_LEN		59
#define	PEAP_TLV_TEMPKEY_LEN		40
#define	PEAP_TLV_IPMK_LEN		40
#define	PEAP_TLV_CMK_LEN		20
#define	PEAP_TLV_NONCE_LEN		32
#define	PEAP_TLV_COMP_MAC_LEN		20
#define	PEAP_TLV_CSK_LEN		128
#define	PEAP_TLV_TK_SEED_LABEL		"client EAP encryption"
#define	PEAP_TLV_IPMK_SEED_LABEL	"Inner Methods Compound Keys"
#define	PEAP_TLV_CSK_SEED_LABEL		"Session Key Generating Function"

#define	PEAP_S_FLAG_SET			0x20
#define	PEAP_L_FLAG_SET			0x80
#define	PEAP_LM_FLAG_SET		0xC0
#define	PEAP_M_FLAG_SET			0x40
#define	PEAP_NO_FLAGS			0x00

#define	EAP_TLS_KEY_LEN			0x40
#define	TLS_RECORD_MAX_SIZE		0x4000

void peap_process(eap_state *esp, u_char id, u_char *inp,
		int len, char *rhostname);

#endif /* PPP_PEAP_H */
