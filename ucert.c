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

enum cert_cont_attr {
	CERT_CT_ATTR_PAYLOAD,
	CERT_CT_ATTR_MAX
};

static const struct blobmsg_policy cert_cont_policy[CERT_CT_ATTR_MAX] = {
	[CERT_CT_ATTR_PAYLOAD] = { .name = "ucert", .type = BLOBMSG_TYPE_TABLE },
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
	[CERT_PL_ATTR_CERTTYPE] = { .name = "certtype", .type = BLOBMSG_TYPE_INT32 },
	[CERT_PL_ATTR_CERTID] = { .name = "certid", .type = BLOBMSG_TYPE_INT32 },
	[CERT_PL_ATTR_VALIDFROMTIME] = { .name = "validfrom", .type = BLOBMSG_TYPE_INT64 },
	[CERT_PL_ATTR_EXPIRETIME] = { .name = "expiresat", .type = BLOBMSG_TYPE_INT64 },
	[CERT_PL_ATTR_PUBKEY] = { .name = "pubkey", .type = BLOBMSG_TYPE_STRING },
	[CERT_PL_ATTR_KEY_FINGERPRINT] = { .name = "fingerprint", .type = BLOBMSG_TYPE_STRING },
};

struct cert_object {
	struct list_head list;
	struct blob_attr *cert[CERT_ATTR_MAX];
};

static int write_file(const char *filename, void *buf, size_t len, bool append) {
	FILE *f;
	size_t outlen;

	f = fopen(filename, append?"a":"w");
	if (!f)
		return 1;

	outlen = fwrite(buf, 1, len, f);
	fclose(f);
	return (outlen == len);
}

static int cert_load(const char *certfile, struct list_head *chain) {
	FILE *f;
	struct blob_attr *certtb[CERT_ATTR_MAX];
	struct blob_attr *bufpt;
	struct cert_object *cobj;
	char filebuf[CERT_BUF_LEN];
	int ret = 0, pret = 0;
	int len, pos = 0;

	f = fopen(certfile, "r");
	if (!f)
		return 1;

	len = fread(&filebuf, 1, CERT_BUF_LEN - 1, f);
	if (len < 64)
		return 1;

	ret = ferror(f) || !feof(f);
	fclose(f);
	if (ret)
		return 1;

	bufpt = (struct blob_attr *)filebuf;
	do {
		pret = blob_parse(bufpt, certtb, cert_policy, CERT_ATTR_MAX);
		if (pret <= 0)
			/* no attributes found */
			break;

		if (pos + blob_pad_len(bufpt) > len)
			/* blob exceeds filebuffer */
			break;
		else
			pos += blob_pad_len(bufpt);

		cobj = calloc(1, sizeof(*cobj));
		memcpy(cobj->cert, &certtb, sizeof(certtb));
		list_add_tail(&cobj->list, chain);
		ret += pret;
		bufpt = blob_next(bufpt);
	/* repeat parsing while there is still enough remaining data in buffer */
	} while(len > pos + sizeof(struct blob_attr));

	return (ret <= 0);
}

static int cert_append(const char *certfile, const char *sigfile) {
	FILE *fs;
	char filebuf[CERT_BUF_LEN];
	struct blob_buf sigbuf;
	struct stat st;
	int len;
	int ret;

	if (stat(certfile, &st) != 0) {
		fprintf(stderr, "certfile %s doesn't exist, can't append.\n", certfile);
		return -1;
	}

	fs = fopen(sigfile, "r");
	if (!fs)
		return 1;

	len = fread(&filebuf, 1, CERT_BUF_LEN - 1, fs);
	ret = ferror(fs) || !feof(fs) || (len < 64);
	fclose(fs);
	if (ret)
		return 1;

	blob_buf_init(&sigbuf, 0);
	blob_put(&sigbuf, CERT_ATTR_SIGNATURE, filebuf, len);
	ret = write_file(certfile, sigbuf.head, blob_raw_len(sigbuf.head), true);
	blob_buf_free(&sigbuf);
	return ret;
}

static int cert_verify_blob(struct blob_attr *cert[CERT_ATTR_MAX],
		       const char *pubkeyfile, const char *pubkeydir) {
	int i;
	char msgfname[256], sigfname[256];
	int ret;
	char tmpdir[] = "/tmp/ucert-XXXXXX";

	if (mkdtemp(tmpdir) == NULL)
		return errno;

	snprintf(msgfname, sizeof(msgfname) - 1, "%s/%s", tmpdir, "payload");
	snprintf(sigfname, sizeof(sigfname) - 1, "%s/%s", tmpdir, "payload.sig");

	for (i = 0; i < CERT_ATTR_MAX; i++) {
		struct blob_attr *v = cert[i];

		if (!v)
			break;

		switch(cert_policy[i].type) {
		case BLOB_ATTR_BINARY:
			write_file(sigfname, blob_data(v), blob_len(v), false);
			break;
		case BLOB_ATTR_NESTED:
			write_file(msgfname, blob_data(v), blob_len(v), false);
			break;
		}
	}

	ret = usign_v(msgfname, pubkeyfile, pubkeydir, sigfname, quiet);

	unlink(msgfname);
	unlink(sigfname);
	rmdir(tmpdir);

	return ret;
}

static int chain_verify(const char *msgfile, const char *pubkeyfile,
			const char *pubkeydir, struct list_head *chain) {
	struct cert_object *cobj;
	struct blob_attr *containertb[CERT_CT_ATTR_MAX];
	struct blob_attr *payloadtb[CERT_PL_ATTR_MAX];
	char tmpdir[] = "/tmp/ucert-XXXXXX";
	char chainedpubkey[256] = {0};
	char extsigfile[256] = {0};
	int ret = 1;
	int checkmsg = 0;

	if (mkdtemp(tmpdir) == NULL)
		return errno;

	if (msgfile)
		checkmsg = -1;

	list_for_each_entry(cobj, chain, list) {
		/* blob has payload, verify that using signature */
		if (cobj->cert[CERT_ATTR_PAYLOAD]) {
			struct timeval tv;
			uint64_t validfrom;
			uint64_t expiresat;
			uint32_t certtype;

			ret = cert_verify_blob(cobj->cert, chainedpubkey[0]?chainedpubkey:pubkeyfile, pubkeydir);
			if (ret)
				goto clean_and_return;

			blobmsg_parse(cert_cont_policy,
				      ARRAY_SIZE(cert_cont_policy),
				      containertb,
				      blob_data(cobj->cert[CERT_ATTR_PAYLOAD]),
				      blob_len(cobj->cert[CERT_ATTR_PAYLOAD]));
			if (!containertb[CERT_CT_ATTR_PAYLOAD]) {
				ret = 1;
				fprintf(stderr, "no ucert in signed payload\n");
				goto clean_and_return;
			}
			blobmsg_parse(cert_payload_policy,
				      ARRAY_SIZE(cert_payload_policy),
				      payloadtb,
				      blobmsg_data(containertb[CERT_CT_ATTR_PAYLOAD]),
				      blobmsg_data_len(containertb[CERT_CT_ATTR_PAYLOAD]));

			if (!payloadtb[CERT_PL_ATTR_CERTTYPE] ||
			    !payloadtb[CERT_PL_ATTR_VALIDFROMTIME] ||
			    !payloadtb[CERT_PL_ATTR_EXPIRETIME] ||
			    !payloadtb[CERT_PL_ATTR_PUBKEY]) {
				ret = 1;
				fprintf(stderr, "missing mandatory ucert attributes\n");
				goto clean_and_return;
			}
			certtype = blobmsg_get_u32(payloadtb[CERT_PL_ATTR_CERTTYPE]);
			validfrom = blobmsg_get_u64(payloadtb[CERT_PL_ATTR_VALIDFROMTIME]);
			expiresat = blobmsg_get_u64(payloadtb[CERT_PL_ATTR_EXPIRETIME]);

			if (certtype != CERTTYPE_AUTH) {
				ret = 2;
				fprintf(stderr, "wrong certificate type\n");
				goto clean_and_return;
			}

			gettimeofday(&tv, NULL);
			if (tv.tv_sec < validfrom ||
			    tv.tv_sec >= expiresat) {
				ret = 3;
				fprintf(stderr, "certificate expired\n");
				goto clean_and_return;
			}

			snprintf(chainedpubkey, sizeof(chainedpubkey) - 1, "%s/%s", tmpdir, "chained-pubkey");
			write_file(chainedpubkey,
				   blobmsg_data(payloadtb[CERT_PL_ATTR_PUBKEY]),
				   blobmsg_data_len(payloadtb[CERT_PL_ATTR_PUBKEY]),
				   false);
		} else {
		/* blob doesn't have payload, verify message using signature */
			if (msgfile) {
				snprintf(extsigfile, sizeof(extsigfile) - 1, "%s/%s", tmpdir, "ext-sig");
				write_file(extsigfile,
					   blob_data(cobj->cert[CERT_ATTR_SIGNATURE]),
					   blob_len(cobj->cert[CERT_ATTR_SIGNATURE]),
					   false);
				checkmsg = ret = usign_v(msgfile,
					      chainedpubkey[0]?chainedpubkey:pubkeyfile,
					      pubkeydir, extsigfile, quiet);
				unlink(extsigfile);
			} else {
				fprintf(stderr, "stray trailing signature without anything to verify!\n");
				ret = 1;
			};
		}
	}

	if (checkmsg == -1)
		fprintf(stderr, "missing signature to verify message!\n");

clean_and_return:
	if (chainedpubkey[0])
		unlink(chainedpubkey);
	rmdir(tmpdir);
	return ret | checkmsg;
}

static void cert_dump_blob(struct blob_attr *cert[CERT_ATTR_MAX]) {
	int i;

	for (i = 0; i < CERT_ATTR_MAX; i++) {
		struct blob_attr *v = cert[i];

		if (!v)
			continue;

		switch(cert_policy[i].type) {
		case BLOB_ATTR_BINARY:
			fprintf(stdout, "signature:\n---\n%s\n---\n", (char *) blob_data(v));
			break;
		case BLOB_ATTR_NESTED:
			fprintf(stdout, "payload:\n---\n%s\n---\n", blobmsg_format_json_indent(blob_data(v), false, 0));
			break;
		}
	}
}

static int cert_dump(const char *certfile) {
	struct cert_object *cobj;
	static LIST_HEAD(certchain);

	if (cert_load(certfile, &certchain)) {
		fprintf(stderr, "cannot parse cert\n");
		return 1;
	}

	list_for_each_entry(cobj, &certchain, list)
		cert_dump_blob(cobj->cert);

	return 0;
}

static int cert_issue(const char *certfile, const char *pubkeyfile, const char *seckeyfile) {
	struct blob_buf certbuf;
	struct blob_buf payloadbuf;
	struct timeval tv;
	struct stat st;
	int pklen, siglen;
	int revoker = 1;
	void *c;
	FILE *pkf, *sigf;
	char pkb[512];
	char sigb[512];
	char fname[256], sfname[256];
	char pkfp[17];
	char tmpdir[] = "/tmp/ucert-XXXXXX";

	if (stat(certfile, &st) == 0) {
		fprintf(stderr, "certfile %s exists, won't overwrite.\n", certfile);
		return -1;
	}

	pkf = fopen(pubkeyfile, "r");
	if (!pkf)
		return -1;

	pklen = fread(pkb, 1, 512, pkf);
	pkb[pklen] = '\0';

	if (pklen < 32)
		return -1;

	fclose(pkf);

	if (usign_f_pubkey(pkfp, pubkeyfile))
		return -1;

	gettimeofday(&tv, NULL);

	if (mkdtemp(tmpdir) == NULL)
		return errno;

	while (revoker >= 0) {
		blob_buf_init(&payloadbuf, 0);
		c = blobmsg_open_table(&payloadbuf, "ucert");
		blobmsg_add_u32(&payloadbuf, "certtype", revoker?CERTTYPE_REVOKE:CERTTYPE_AUTH);
		blobmsg_add_u64(&payloadbuf, "validfrom", tv.tv_sec);
		if (!revoker) {
			blobmsg_add_u64(&payloadbuf, "expiresat", tv.tv_sec + 60 * 60 * 24 * 365);
			blobmsg_add_string(&payloadbuf, "pubkey", pkb);
		} else {
			blobmsg_add_string(&payloadbuf, "fingerprint", pkfp);
		}

		blobmsg_close_table(&payloadbuf, c);

		snprintf(fname, sizeof(fname) - 1, "%s/%s", tmpdir, revoker?"revoker":"payload");
		write_file(fname, blob_data(payloadbuf.head), blob_len(payloadbuf.head), false);

		snprintf(sfname, sizeof(sfname) - 1, "%s/%s", tmpdir, revoker?"revoker.sig":"payload.sig");
		if (usign_s(fname, seckeyfile, sfname, quiet))
			return 1;

		sigf = fopen(sfname, "r");
		if (!sigf)
			return 1;

		siglen = fread(sigb, 1, 1024, sigf);
		if (siglen < 1)
			return 1;

		sigb[siglen-1] = '\0';
		fclose(sigf);

		unlink(fname);
		unlink(sfname);

		blob_buf_init(&certbuf, 0);
		blob_put(&certbuf, CERT_ATTR_SIGNATURE, sigb, siglen);
		blob_put(&certbuf, CERT_ATTR_PAYLOAD, blob_data(payloadbuf.head), blob_len(payloadbuf.head));
		snprintf(fname, sizeof(fname) - 1, "%s%s", certfile, revoker?".revoke":"");
		write_file(fname, certbuf.head, blob_raw_len(certbuf.head), false);
		blob_buf_free(&certbuf);
		blob_buf_free(&payloadbuf);

		revoker--;
	}

	rmdir(tmpdir);

	return 0;
}

static int cert_process_revoker(const char *certfile) {
	fprintf(stderr, "not implemented\n");
	return 1;
}

static int cert_verify(const char *certfile, const char *pubkeyfile, const char *pubkeydir, const char *msgfile) {
	static LIST_HEAD(certchain);

	if (cert_load(certfile, &certchain)) {
		fprintf(stderr, "cannot parse cert\n");
		return 1;
	}

	return chain_verify(msgfile, pubkeyfile, pubkeydir, &certchain);
}

static int usage(const char *cmd)
{
	fprintf(stderr,
		"Usage: %s <command> <options>\n"
		"Commands:\n"
		"  -A:			append (needs -c and -x)\n"
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
		case 'q':
			quiet = true;
			break;
		case 's':
			seckeyfile = optarg;
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
		if (certfile && sigfile)
			return cert_append(certfile, sigfile);
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
