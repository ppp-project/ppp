/*	From NetBSD: bpf_filter.c,v 1.12 1996/02/13 22:00:00 christos Exp */

/*
 * Copyright (c) 1990, 1991, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	From: @(#)bpf_filter.c	8.1 (Berkeley) 6/10/93
 *	$Id: bpf_filter.c,v 1.1 1996/04/04 02:45:45 paulus Exp $
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <net/ppp_defs.h>
#include "ppp_mod.h"

#ifdef SVR4
#ifndef __GNUC__
#include <sys/byteorder.h>	/* for ntohl, etc. */
#else
/* make sure we don't get the gnu "fixed" one! */
#include "/usr/include/sys/byteorder.h"
#endif
#endif

#ifdef OSF1
#include <net/net_globals.h>
#endif
#include <netinet/in.h>

#ifdef AIX4
#define _NETINET_IN_SYSTM_H_
typedef u_long  n_long;
#else
#include <netinet/in_systm.h>
#endif

#if !(defined(__i386__) || defined(__m68k__))	/* any others? */
#define BPF_ALIGN
#endif

#ifndef BPF_ALIGN
#define EXTRACT_SHORT(p)	((ushort)ntohs(*(ushort *)p))
#define EXTRACT_LONG(p)		(ntohl(*(uint *)p))
#else
#define EXTRACT_SHORT(p)\
	((ushort)\
		((ushort)*((u_char *)p+0)<<8|\
		 (ushort)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((uint)*((u_char *)p+0)<<24|\
		 (uint)*((u_char *)p+1)<<16|\
		 (uint)*((u_char *)p+2)<<8|\
		 (uint)*((u_char *)p+3)<<0)
#endif

#ifdef _KERNEL
#define MINDEX(len, m, k) \
{ \
	len = m->b_wptr - m->b_rptr; \
	while (k >= len) { \
		k -= len; \
		m = m->b_cont; \
		if (m == 0) \
			return 0; \
		len = m->b_wptr - m->b_rptr; \
	} \
}

static int m_xword __P((mblk_t *, int, int *));
static int m_xhalf __P((mblk_t *, int, int *));

static int
m_xword(m, k, err)
	register mblk_t *m;
	register int k, *err;
{
	register int len;
	register uchar_t *cp, *np;
	register mblk_t *m0;

	MINDEX(len, m, k);
	cp = m->b_rptr + k;
	if (len - k >= 4) {
		*err = 0;
		return EXTRACT_LONG(cp);
	}
	m0 = m->b_cont;
	if (m0 == 0 || m0->b_wptr - m0->b_rptr + len - k < 4)
		goto bad;
	*err = 0;
	np = m0->b_rptr;
	switch (len - k) {

	case 1:
		return (cp[0] << 24) | (np[0] << 16) | (np[1] << 8) | np[2];

	case 2:
		return (cp[0] << 24) | (cp[1] << 16) | (np[0] << 8) | np[1];

	default:
		return (cp[0] << 24) | (cp[1] << 16) | (cp[2] << 8) | np[0];
	}
    bad:
	*err = 1;
	return 0;
}

static int
m_xhalf(m, k, err)
	register mblk_t *m;
	register int k, *err;
{
	register int len;
	register uchar_t *cp;
	register mblk_t *m0;

	MINDEX(len, m, k);
	cp = m->b_rptr + k;
	if (len - k >= 2) {
		*err = 0;
		return EXTRACT_SHORT(cp);
	}
	m0 = m->b_cont;
	if (m0 == 0)
		goto bad;
	*err = 0;
	return (cp[0] << 8) | m0->b_rptr[0];
 bad:
	*err = 1;
	return 0;
}
#endif

#include <net/bpf.h>

/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 */
uint
bpf_filter(pc, p, wirelen, buflen)
	register struct bpf_insn *pc;
	register uchar_t *p;
	uint wirelen;
	register uint buflen;
{
	register uint A = 0, X = 0;
	register int k;
	int mem[BPF_MEMWORDS];

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (uint)-1;
	--pc;
	while (1) {
		++pc;
		switch (pc->code) {

		default:
#ifdef _KERNEL
			return 0;
#else
			abort();
#endif			
		case BPF_RET|BPF_K:
			return (uint)pc->k;

		case BPF_RET|BPF_A:
			return (uint)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k + sizeof(int) > buflen) {
#ifdef _KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xword((mblk_t *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k + sizeof(short int) > buflen) {
#ifdef _KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xhalf((mblk_t *)p, k, &merr);
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			if (k >= buflen) {
#ifdef _KERNEL
				register mblk_t *m;
				register int len;

				if (buflen != 0)
					return 0;
				m = (mblk_t *)p;
				MINDEX(len, m, k);
				A = m->b_rptr[k];
				continue;
#else
				return 0;
#endif
			}
			A = p[k];
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (k + sizeof(int) > buflen) {
#ifdef _KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xword((mblk_t *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (k + sizeof(short int) > buflen) {
#ifdef _KERNEL
				int merr;

				if (buflen != 0)
					return 0;
				A = m_xhalf((mblk_t *)p, k, &merr);
				if (merr != 0)
					return 0;
				continue;
#else
				return 0;
#endif
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if (k >= buflen) {
#ifdef _KERNEL
				register mblk_t *m;
				register int len;

				if (buflen != 0)
					return 0;
				m = (mblk_t *)p;
				MINDEX(len, m, k);
				A = m->b_rptr[k];
				continue;
#else
				return 0;
#endif
			}
			A = p[k];
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if (k >= buflen) {
#ifdef _KERNEL
				register mblk_t *m;
				register int len;

				if (buflen != 0)
					return 0;
				m = (mblk_t *)p;
				MINDEX(len, m, k);
				X = (m->b_rptr[k] & 0xf) << 2;
				continue;
#else
				return 0;
#endif
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;
			
		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			A = -A;
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

#ifdef _KERNEL
/*
 * Return true if the 'fcode' is a valid filter program.
 * The constraints are that each jump be forward and to a valid
 * code.  The code must terminate with either an accept or reject. 
 * 'valid' is an array for use by the routine (it must be at least
 * 'len' bytes long).  
 *
 * The kernel needs to be able to verify an application's filter code.
 * Otherwise, a bogus program could easily crash the system.
 */
int
bpf_validate(f, len)
	struct bpf_insn *f;
	int len;
{
	register int i;
	register struct bpf_insn *p;

	for (i = 0; i < len; ++i) {
		/*
		 * Check that that jumps are forward, and within 
		 * the code block.
		 */
		p = &f[i];
		if (BPF_CLASS(p->code) == BPF_JMP) {
			register int from = i + 1;

			if (BPF_OP(p->code) == BPF_JA) {
				if (from + p->k >= len)
					return 0;
			}
			else if (from + p->jt >= len || from + p->jf >= len)
				return 0;
		}
		/*
		 * Check that memory operations use valid addresses.
		 */
		if ((BPF_CLASS(p->code) == BPF_ST ||
		     (BPF_CLASS(p->code) == BPF_LD && 
		      (p->code & 0xe0) == BPF_MEM)) &&
		    (p->k >= BPF_MEMWORDS || p->k < 0))
			return 0;
		/*
		 * Check for constant division by 0.
		 */
		if (p->code == (BPF_ALU|BPF_DIV|BPF_K) && p->k == 0)
			return 0;
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
#endif
