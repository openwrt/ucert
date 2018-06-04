/*
 * Copyright (C) 2018 Daniel Golle <daniel@makrotopia.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>
#include <libubox/blob.h>
#include <libubox/list.h>
#include <libubox/vlist.h>
#include <libubox/blobmsg_json.h>

static enum {
	CMD_APPEND,
	CMD_DUMP,
	CMD_ISSUE,
	CMD_REVOKE,
	CMD_VERIFY,
	CMD_NONE,
} cmd = CMD_NONE;

static bool quiet;

static int cert_append(const char *certfile, const char *pubkeyfile, const char *sigfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_dump(const char *certfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_issue(const char *certfile, const char *pubkeyfile, const char *seckeyfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_process_revoker(const char *certfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_verify(const char *certfile, const char *pubkeyfile, const char *pubkeydir, const char *msgfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int usage(const char *cmd)
{
	fprintf(stderr,
		"Usage: %s <command> <options>\n"
		"Commands:\n"
		"  -A:			append (needs -c and -p and/or -x)\n"
		"  -D:			dump\n"
		"  -I:			issue cert and revoker (needs -c and -p and -s)\n"
		"  -R:			process revoker certificate (needs -c)\n"
		"  -V:			verify (needs -c and -p|-P)\n"
		"Options:\n"
		"  -c <file>:		certificate file\n"
		"  -m <file>:		message file (verify only)\n"
		"  -p <file>:		public key file\n"
		"  -P <path>:		public key directory (verify only)\n"
		"  -q:			quiet (do not print verification result, use return code only)\n"
		"  -s <file>:		secret key file (issue only)\n"
		"  -x <file>:		signature file\n"
		"\n",
		cmd);
	return 1;
}

int main(int argc, char *argv[]) {
	int ch;
	const char *msgfile = NULL;
	const char *sigfile = NULL;
	const char *pubkeyfile = NULL;
	const char *pubkeydir = NULL;
	const char *certfile = NULL;
	const char *seckeyfile = NULL;

	quiet = false;
	while ((ch = getopt(argc, argv, "ADIRVc:m:p:P:qs:x:")) != -1) {
		switch (ch) {
		case 'A':
			cmd = CMD_APPEND;
			break;
		case 'D':
			cmd = CMD_DUMP;
			break;
		case 'I':
			cmd = CMD_ISSUE;
			break;
		case 'R':
			cmd = CMD_REVOKE;
			break;
		case 'V':
			cmd = CMD_VERIFY;
			break;
		case 'c':
			certfile = optarg;
			break;
		case 'm':
			msgfile = optarg;
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 'P':
			pubkeydir = optarg;
			break;
		case 's':
			seckeyfile = optarg;
			break;
		case 'q':
			quiet = true;
			break;
		case 'x':
			sigfile = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	switch (cmd) {
	case CMD_APPEND:
		if (certfile && (pubkeyfile || sigfile))
			return cert_append(certfile, pubkeyfile, sigfile);
		else
			return usage(argv[0]);
	case CMD_DUMP:
		if (certfile)
			return cert_dump(certfile);
		else
			return usage(argv[0]);
	case CMD_ISSUE:
		if (certfile && pubkeyfile && seckeyfile)
			return cert_issue(certfile, pubkeyfile, seckeyfile);
		else
			return usage(argv[0]);
	case CMD_REVOKE:
		if (certfile)
			return cert_process_revoker(certfile);
		else
			return usage(argv[0]);
	case CMD_VERIFY:
		if (certfile && (pubkeyfile || pubkeydir))
			return cert_verify(certfile, pubkeyfile, pubkeydir, msgfile);
		else
			return usage(argv[0]);
	case CMD_NONE:
		return usage(argv[0]);
	}

	/* unreachable */
	return usage(argv[0]);
}
