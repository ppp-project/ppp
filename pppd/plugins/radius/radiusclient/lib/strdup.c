/*
 * $Id: strdup.c,v 1.2 2002/02/27 15:51:20 dfs Exp $
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

/*
 * Function: strdup
 *
 * Purpose:  strdup replacement for systems which lack it
 *
 */

char *strdup(char *str)
{
	char *p;

	if (str == NULL)
		return NULL;

	if ((p = (char *)malloc(strlen(str)+1)) == NULL)
		return p;

	return strcpy(p, str);
}
