/*
 * $Id: env.c,v 1.2 2002/02/27 15:51:20 dfs Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <radiusclient.h>

/*
 * Function: rc_new_env
 *
 * Purpose: allocate space for a new environment
 *
 */

ENV *rc_new_env(int size)
{
	ENV *p;

	if (size < 1)
		return NULL;

	if ((p = malloc(sizeof(*p))) == NULL)
		return NULL;

	if ((p->env = malloc(size * sizeof(char *))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_new_env: out of memory");
		free(p);
		return NULL;
	}

	p->env[0] = NULL;

	p->size = 0;
	p->maxsize = size;

	return p;
}

/*
 * Function: rc_free_env
 *
 * Purpose: free the space used by an env structure
 *
 */

void rc_free_env(ENV *env)
{
	free(env->env);
	free(env);
}

/*
 * Function: rc_add_env
 *
 * Purpose: add an environment entry
 *
 */

int rc_add_env(ENV *env, char *name, char *value)
{
	int i;
	char *new_env;

	for (i = 0; env->env[i] != NULL; i++)
	{
		if (strncmp(env->env[i], name, MAX(strchr(env->env[i], '=') - env->env[i],strlen(name))) == 0)
			break;
	}

	if (env->env[i])
	{
		if ((new_env = realloc(env->env[i], strlen(name)+strlen(value)+2)) == NULL)
			return (-1);

		env->env[i] = new_env;

		sprintf(env->env[i],"%s=%s", name, value);
	} else {
		if (env->size == (env->maxsize-1)) {
			rc_log(LOG_CRIT, "rc_add_env: not enough space for environment (increase ENV_SIZE)");
			return (-1);
		}

		if ((env->env[env->size] = malloc(strlen(name)+strlen(value)+2)) == NULL) {
			rc_log(LOG_CRIT, "rc_add_env: out of memory");
			return (-1);
		}

		sprintf(env->env[env->size],"%s=%s", name, value);

		env->size++;

		env->env[env->size] = NULL;
	}

	return 0;
}

/*
 * Function: rc_import_env
 *
 * Purpose: imports an array of null-terminated strings
 *
 */

int rc_import_env(ENV *env, char **import)
{
	char *es;

	while (*import)
	{
		es = strchr(*import, '=');

		if (!es)
		{
			import++;
			continue;
		}

		/* ok, i grant thats not very clean... */
		*es = '\0';

		if (rc_add_env(env, *import, es+1) < 0)
		{
			*es = '=';
			return (-1);
		}

		*es = '=';

		import++;
	}

	return 0;
}
