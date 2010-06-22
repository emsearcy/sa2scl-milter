/*
 * Copyright (c) 2010 Eric Searcy
 * Copyright (c) 2003-2006 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#ifdef __linux__
#include <grp.h>
#endif
#include <libmilter/mfapi.h>

extern void	 die(const char *);

static int		 debug = 0;

struct context {
	int		 sclvalue;
	char		 host_name[128];
	char		 host_addr[64];
};

static sfsistat		 cb_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat		 cb_envrcpt(SMFICTX *, char **);
static sfsistat		 cb_header(SMFICTX *, char *, char *);
static sfsistat		 cb_eoh(SMFICTX *);
static sfsistat		 cb_eom(SMFICTX *);
static sfsistat		 cb_close(SMFICTX *);
static void		 usage(const char *);
static void		 msg(int, struct context *, const char *, ...);

#define USER		"_sclmilt"
#define OCONN		"unix:/var/spool/sa2scl-milter/sock"

#if __linux__
#define	ST_MTIME st_mtime
extern size_t	 strlcpy(char *, const char *, size_t);
#else
#define	ST_MTIME st_mtimespec
#endif

static sfsistat
cb_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa)
{
	struct context *context;

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		msg(LOG_ERR, NULL, "cb_connect: calloc: %s", strerror(errno));
		return (SMFIS_ACCEPT);
	}
	if (smfi_setpriv(ctx, context) != MI_SUCCESS) {
		free(context);
		msg(LOG_ERR, NULL, "cb_connect: smfi_setpriv");
		return (SMFIS_ACCEPT);
	}
	context->sclvalue = -1;

	strlcpy(context->host_name, name, sizeof(context->host_name));
	strlcpy(context->host_addr, "unknown", sizeof(context->host_addr));
	if (sa) {
		switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)sa;

			if (inet_ntop(AF_INET, &sin->sin_addr.s_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

			if (inet_ntop(AF_INET6, &sin6->sin6_addr,
			    context->host_addr, sizeof(context->host_addr)) ==
			    NULL)
				msg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s",
				    strerror(errno));
			break;
		}
		}
	}
	msg(LOG_DEBUG, context, "cb_connect('%s', '%s')",
	    context->host_name, context->host_addr);
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envrcpt(SMFICTX *ctx, char **args)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_envrcpt: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	if (*args != NULL) {
		msg(LOG_DEBUG, context, "cb_envrcpt('%s')", *args);
		if (!strcasecmp(args[0], "abuse@insightsnow.com")) {
			context->sclvalue = 0;
		}
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_header(SMFICTX *ctx, char *name, char *value)
{
	struct context *context;
	const struct action *action;
	int salevel;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, context, "cb_header: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_header('%s', '%s')", name, value);

	if (context->sclvalue != -1) return (SMFIS_CONTINUE);

	if (!strcasecmp(name, "X-Spam-Level")) {
		salevel = strlen(value);

		switch (salevel) {
		case 0:
		case 1:
			context->sclvalue = 1;
			break;
		case 2:
			context->sclvalue = 2;
			break;
		case 3:
			context->sclvalue = 3;
			break;
		case 4:
			context->sclvalue = 4;
			break;
		case 5:
			context->sclvalue = 5;
			break;
		case 6:
			context->sclvalue = 6;
			break;
		case 7:
		case 8:
			context->sclvalue = 7;
			break;
		case 9:
		case 10:
			context->sclvalue = 8;
			break;
		default:
			if (salevel > 10) {
				context->sclvalue = 9;
			} else {
				msg(LOG_ERR, NULL, "cb_header: X-Spam-Level parsed %d",
					salevel);
			}
			break;
		}
	}
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eoh(SMFICTX *ctx)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eoh: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eoh()");

	if (context->sclvalue == -1) {
		context->sclvalue = 0;
	}

	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eom(SMFICTX *ctx)
{
	struct context *context;
	char sclstr[16];

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		msg(LOG_ERR, NULL, "cb_eom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	msg(LOG_DEBUG, context, "cb_eom()");

	if (context->sclvalue != -1) {
		snprintf(sclstr, 16, "%d", context->sclvalue);
		if (smfi_addheader(ctx, "X-MS-Exchange-Organization-SCL", sclstr) != MI_SUCCESS)
				msg(LOG_ERR, context, "cb_eom: smfi_addheader");
	}
	return (SMFIS_ACCEPT);
}

static sfsistat
cb_close(SMFICTX *ctx)
{
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	msg(LOG_DEBUG, context, "cb_close()");
	if (context != NULL) {
		smfi_setpriv(ctx, NULL);
		free(context);
	}
	return (SMFIS_CONTINUE);
}

struct smfiDesc smfilter = {
	"sa2scl-milter",	/* filter name */
	SMFI_VERSION,		/* version code -- do not change */
	SMFIF_ADDHDRS,		/* flags */
	cb_connect,		/* connection info filter */
	NULL,			/* SMTP HELO command filter */
	NULL,			/* envelope sender filter */
	cb_envrcpt,		/* envelope recipient filter */
	cb_header,		/* header filter */
	cb_eoh,			/* end of header */
	NULL,			/* body block */
	cb_eom,			/* end of message */
	NULL,			/* message aborted */
	cb_close		/* connection cleanup */
};

static void
msg(int priority, struct context *context, const char *fmt, ...)
{
	va_list ap;
	char msg[8192];

	va_start(ap, fmt);
	if (context != NULL)
		snprintf(msg, sizeof(msg), "%s: ", context->host_addr);
	else
		msg[0] = 0;
	vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
	if (debug)
		printf("syslog: %s\n", msg);
	else
		syslog(priority, "%s", msg);
	va_end(ap);
}

static void
usage(const char *argv0)
{
	fprintf(stderr, "usage: %s [-d] [-u user] "
	    "[-p pipe]\n", argv0);
	exit(1);
}

void
die(const char *reason)
{
	msg(LOG_ERR, NULL, "die: %s", reason);
	smfi_stop();
	sleep(60);
	/* not reached, smfi_stop() kills thread */
	abort();
}

int
main(int argc, char **argv)
{
	int ch;
	mode_t omask;
	const char *oconn = OCONN;
	const char *user = USER;
	const char *group = "";
	sfsistat r = MI_FAILURE;
	const char *ofile = NULL;

	tzset();
	openlog("sa2scl-milter", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	while ((ch = getopt(argc, argv, "dg:p:u:")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'g':
			group = optarg;
			break;
		case 'p':
			oconn = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (argc != optind) {
		fprintf(stderr, "unknown command line argument: %s ...",
		    argv[optind]);
		usage(argv[0]);
	}

	if (!strncmp(oconn, "unix:", 5))
		ofile = oconn + 5;
	else if (!strncmp(oconn, "local:", 6))
		ofile = oconn + 6;
	if (ofile != NULL)
		unlink(ofile);

	/* drop privileges */
	if (!getuid()) {
		struct passwd *pw;
		struct group *gr;

		if ((pw = getpwnam(user)) == NULL) {
			fprintf(stderr, "getpwnam: %s: %s\n", user,
			    strerror(errno));
			return (1);
		}
		if (strlen(group) == 0 || (gr = getgrnam(group)) == NULL) {
			/* use primary group of user */
			setgroups(1, &pw->pw_gid);
			if (setegid(pw->pw_gid) || setgid(pw->pw_gid)) {
				fprintf(stderr, "setgid: %s\n", strerror(errno));
				return (1);
			}
			omask = 0177;
		} else {
			/* custom group */
			setgroups(1, &gr->gr_gid);
			if (setegid(gr->gr_gid) || setgid(gr->gr_gid)) {
				fprintf(stderr, "setgid: %s\n", strerror(errno));
				return (1);
			}
			omask = 0117;
		}
		if (
#if ! ( __linux__ )
		    seteuid(pw->pw_uid) ||
#endif
		    setuid(pw->pw_uid)) {
			fprintf(stderr, "setuid: %s\n", strerror(errno));
			return (1);
		}
	}

	if (smfi_setconn((char *)oconn) != MI_SUCCESS) {
		fprintf(stderr, "smfi_setconn: %s: failed\n", oconn);
		goto done;
	}

	if (smfi_register(smfilter) != MI_SUCCESS) {
		fprintf(stderr, "smfi_register: failed\n");
		goto done;
	}

	/* daemonize (detach from controlling terminal) */
	if (!debug && daemon(0, 0)) {
		fprintf(stderr, "daemon: %s\n", strerror(errno));
		goto done;
	}
	umask(omask);

	msg(LOG_INFO, NULL, "smfi_main: started");
	r = smfi_main();
	if (r != MI_SUCCESS)
		msg(LOG_ERR, NULL, "smfi_main: terminating due to error");
	else
		msg(LOG_INFO, NULL, "smfi_main: terminating without error");

done:
	return (r);
}

/* vim: ai noet sw=8 ts=8
 */
