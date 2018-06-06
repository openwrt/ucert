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
#include <libubox/utils.h>
#include <libubox/list.h>
#include <libubox/vlist.h>
#include <libubox/blobmsg_json.h>

#include "usign.h"

#define CERT_BUF_LEN 4096

static enum {
	CMD_APPEND,
	CMD_DUMP,
	CMD_ISSUE,
	CMD_REVOKE,
	CMD_VERIFY,
	CMD_NONE,
} cmd = CMD_NONE;

static bool quiet;

enum cert_attr {
	CERT_ATTR_SIGNATURE,
	CERT_ATTR_PAYLOAD,
	CERT_ATTR_MAX
};

static const struct blob_attr_info cert_policy[CERT_ATTR_MAX] = {
	[CERT_ATTR_SIGNATURE] = { .type = BLOB_ATTR_BINARY },
	[CERT_ATTR_PAYLOAD] = { .type = BLOB_ATTR_NESTED },
};

enum cert_payload_attr {
	CERT_PL_ATTR_CERTTYPE,
	CERT_PL_ATTR_CERTID,
	CERT_PL_ATTR_VALIDFROMTIME,
	CERT_PL_ATTR_EXPIRETIME,
	CERT_PL_ATTR_PUBKEY,
	CERT_PL_ATTR_KEY_FINGERPRINT,
	CERT_PL_ATTR_MAX
};

enum certtype_id {
	CERTTYPE_UNSPEC,
	CERTTYPE_AUTH,
	CERTTYPE_REVOKE
};

static const struct blobmsg_policy cert_payload_policy[CERT_PL_ATTR_MAX] = {
	[CERT_PL_ATTR_CERTTYPE] = { .type = BLOBMSG_TYPE_INT8 },
	[CERT_PL_ATTR_CERTID] = { .type = BLOBMSG_TYPE_INT64 },
	[CERT_PL_ATTR_VALIDFROMTIME] = { .type = BLOBMSG_TYPE_INT64 },
	[CERT_PL_ATTR_EXPIRETIME] = { .type = BLOBMSG_TYPE_INT64 },
	[CERT_PL_ATTR_PUBKEY] = { .type = BLOBMSG_TYPE_STRING },
	[CERT_PL_ATTR_KEY_FINGERPRINT] = { .type = BLOBMSG_TYPE_STRING },
};


static int cert_load(const char *certfile, struct blob_attr *certtb[]) {
	FILE *f;
	struct blob_buf certbuf;
	int ret = 0;
	char filebuf[CERT_BUF_LEN];
	int len;

	blob_buf_init(&certbuf, 0);

	f = fopen(certfile, "r");
	if (!f)
		return 1;

	do {
		len = fread(&filebuf, 1, CERT_BUF_LEN - 1, f);
		blob_put_raw(&certbuf, filebuf, len);
	} while(!feof(f) && !ferror(f));

	ret = ferror(f);
	fclose(f);

	if (ret)
		return 1;

	return (blob_parse(certbuf.head, certtb, cert_policy, CERT_ATTR_MAX) != 0);
}

static int cert_append(const char *certfile, const char *pubkeyfile, const char *sigfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_dump(const char *certfile) {
	struct blob_attr *certtb[CERT_ATTR_MAX];

	if (cert_load(certfile, certtb)) {
		fprintf(stderr, "cannot parse cert\n");
		return 1;
	}

	return 0;
}

static int cert_issue(const char *certfile, const char *pubkeyfile, const char *seckeyfile) {
	struct blob_buf certbuf;
	struct blob_buf payloadbuf;

	blob_buf_init(&payloadbuf, 0);
/*	usign_s() */

	blob_buf_init(&certbuf, 0);

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
