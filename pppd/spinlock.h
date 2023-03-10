/* 
   Unix SMB/CIFS implementation.

   trivial database library 

   Copyright (C) Anton Blanchard                   2001
   
     ** NOTE! The following LGPL license applies to the tdb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef PPP_SPINLOCK_H
#define PPP_SPINLOCK_H

#include "pppdconf.h"

#include "tdb.h"

#ifdef USE_SPINLOCKS

#define RWLOCK_BIAS 0x1000UL

/* OS SPECIFIC */
#define MAX_BUSY_LOOPS 1000
#undef USE_SCHED_YIELD

/* ARCH SPECIFIC */
/* We should make sure these are padded to a cache line */
#if defined(SPARC_SPINLOCKS)
typedef volatile char spinlock_t;
#elif defined(POWERPC_SPINLOCKS)
typedef volatile unsigned long spinlock_t;
#elif defined(INTEL_SPINLOCKS)
typedef volatile int spinlock_t;
#elif defined(MIPS_SPINLOCKS)
typedef volatile unsigned long spinlock_t;
#else
#error Need to implement spinlock code in spinlock.h
#endif

typedef struct {
	spinlock_t lock;
	volatile int count;
} tdb_rwlock_t;

int tdb_spinlock(TDB_CONTEXT *tdb, int list, int rw_type);
int tdb_spinunlock(TDB_CONTEXT *tdb, int list, int rw_type);
int tdb_create_rwlocks(int fd, unsigned int hash_size);
int tdb_clear_spinlocks(TDB_CONTEXT *tdb);

#define TDB_SPINLOCK_SIZE(hash_size) (((hash_size) + 1) * sizeof(tdb_rwlock_t))

#else /* !USE_SPINLOCKS */
#if 0
#define tdb_create_rwlocks(fd, hash_size) 0
#define tdb_spinlock(tdb, list, rw_type) (-1)
#define tdb_spinunlock(tdb, list, rw_type) (-1)
#else
int tdb_spinlock(TDB_CONTEXT *tdb, int list, int rw_type);
int tdb_spinunlock(TDB_CONTEXT *tdb, int list, int rw_type);
int tdb_create_rwlocks(int fd, unsigned int hash_size);
#endif
int tdb_clear_spinlocks(TDB_CONTEXT *tdb);
#define TDB_SPINLOCK_SIZE(hash_size) 0

#endif

#endif // PPP_SPINLOCK_H
