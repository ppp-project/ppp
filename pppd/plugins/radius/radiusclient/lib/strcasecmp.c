/*
 * $Id: strcasecmp.c,v 1.1 2002/01/22 16:03:02 dfs Exp $
 *
 * Copyright (C) 1996 Lars Fenneberg and Christian Graefe
 *
 * This file is provided under the terms and conditions of the GNU general 
 * public license, version 2 or any later version, incorporated herein by 
 * reference. 
 *
 */

#include "config.h"
#include "includes.h"

#ifdef HAVE_STRICMP
# define strcasecmp(a,b)	stricmp(a,b)
#else

/*
 * Function: strcasecmp
 *
 * Purpose:  strcasecmp replacement for systems which lack strcasecmp and
 *			 stricmp
 */

int strcasecmp(char *s1, char *s2)
{
	while (*s1 && *s2 && toupper(*s1) == toupper(*s2))
    	s1++, s2++;
        
    if (!*s1 && !*s2)
    	return 0;    
    else
    	return (toupper(*s1) - toupper(*s2));                            
}
#endif
