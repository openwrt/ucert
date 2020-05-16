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
#include <errno.h>
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
#ifndef UCERT_STRIP_MESSAGES
#define DPRINTF(format, ...)								\
	do {										\
		if (!quiet)								\
			fprintf(stderr, "%s: " format, __func__, ## __VA_ARGS__);	\
	} while (0)
#else
#define DPRINTF(format, ...) do { } while (0)
#endif

/*
 * ucert structure
 * |               BLOB                    |
 * |    SIGNATURE    |       PAYLOAD       |
 * |                 |[ BLOBMSG CONTAINER ]|
 * |                 |[[T,i,v,e,f,pubkey ]]|
 */
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

/* list to store certificate chain at runtime */
struct cert_object {
	struct list_head list;
	struct blob_attr *cert[CERT_ATTR_MAX];
};

/* write buffer to file */
static bool write_file(const char *filename, void *buf, size_t len, bool append) {
	FILE *f;
	size_t outlen;

	f = fopen(filename, append?"a":"w");
	if (!f)
		return false;

	outlen = fwrite(buf, 1, len, f);
	fclose(f);
	return (outlen == len);
}

/* reads a whole file to a buffer - returns -1 on errors and sets errno */
static ssize_t read_file(const char *filename, void *buf, size_t len, size_t minlen) {
	FILE *f;
	ssize_t ret;

	f = fopen(filename, "r");
	if (!f)
		return -1;

	ret = fread(buf, 1, len, f);

	/* Ensure that feof() yields the correct result when the file is exactly
	 * len bytes long */
	fgetc(f);

	if (ferror(f)) {
		ret = -1;
	} else if (!feof(f)) {
		errno = EOVERFLOW;
		ret = -1;
	} else if ((size_t)ret < minlen) {
		errno = EINVAL;
		ret = -1;
	}

	fclose(f);
	return ret;
}

/* load certfile into list */
static int cert_load(const char *certfile, struct list_head *chain) {
	struct blob_attr *certtb[CERT_ATTR_MAX];
	struct blob_attr *bufpt;
	struct cert_object *cobj;
	char filebuf[CERT_BUF_LEN], *end;
	int ret = 1;
	ssize_t len;

	len = read_file(certfile, filebuf, sizeof(filebuf) - 1, 0);
	if (len < 0) {
		if (!quiet)
			perror("Unable to load certificate file");
		return 1;
	}

	bufpt = (struct blob_attr *)filebuf;
	end = filebuf + len;

	while (true) {
		len = end - (char *)bufpt;
		if (len <= 0)
			break;

		if (blob_parse_untrusted(bufpt, len, certtb, cert_policy, CERT_ATTR_MAX) <= 0)
			/* no attributes found */
			break;

		if (!certtb[CERT_ATTR_SIGNATURE])
			/* no signature -> drop */
			break;

		cobj = calloc(1, sizeof(*cobj));
		cobj->cert[CERT_ATTR_SIGNATURE] = blob_memdup(certtb[CERT_ATTR_SIGNATURE]);
		if (certtb[CERT_ATTR_PAYLOAD])
			cobj->cert[CERT_ATTR_PAYLOAD] = blob_memdup(certtb[CERT_ATTR_PAYLOAD]);

		list_add_tail(&cobj->list, chain);
		ret = 0;

		/* Repeat parsing while there is still enough remaining data in buffer
		 *
		 * Note that blob_next() is only valid for untrusted data because blob_parse_untrusted()
		 * verified that the buffer contains at least one blob, and that it is completely contained
		 * in the buffer */
		bufpt = blob_next(bufpt);
	}

	return ret;
}

#ifdef UCERT_FULL
/* append signature to certfile */
static int cert_append(const char *certfile, const char *sigfile) {
	char filebuf[CERT_BUF_LEN];
	struct blob_buf sigbuf = {0};
	ssize_t len;
	int ret;

	len = read_file(sigfile, filebuf, sizeof(filebuf) - 1, 64);
	if (len < 0) {
		if (!quiet)
			perror("Unable to load signature file");

		return 1;
	}

	blob_buf_init(&sigbuf, 0);
	blob_put(&sigbuf, CERT_ATTR_SIGNATURE, filebuf, len);
	ret = write_file(certfile, sigbuf.head, blob_raw_len(sigbuf.head), true);
	blob_buf_free(&sigbuf);
	return ret;
}
#endif

/* verify the signature of a single chain element */
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

/* verify cert chain (and message) */
static int chain_verify(const char *msgfile, const char *pubkeyfile,
			const char *pubkeydir, struct list_head *chain) {
	struct cert_object *cobj;
	struct blob_attr *containertb[CERT_CT_ATTR_MAX];
	struct blob_attr *payloadtb[CERT_PL_ATTR_MAX];
	char tmpdir[] = "/tmp/ucert-XXXXXX";
	char chainedpubkey[256] = {0};
	char chainedfp[17] = {0};
	char extsigfile[256] = {0};
	int ret = 1;
	int checkmsg = 0;
	struct timeval tv;

	if (mkdtemp(tmpdir) == NULL)
		return errno;

	if (msgfile)
		checkmsg = -1;

	gettimeofday(&tv, NULL);

	list_for_each_entry(cobj, chain, list) {
		/* blob has payload, verify that using signature */
		if (cobj->cert[CERT_ATTR_PAYLOAD]) {
			time_t validfrom;
			time_t expiresat;
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
				DPRINTF("no ucert in signed payload\n");
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
				DPRINTF("missing mandatory ucert attributes\n");
				goto clean_and_return;
			}
			certtype = blobmsg_get_u32(payloadtb[CERT_PL_ATTR_CERTTYPE]);
			validfrom = blobmsg_get_u64(payloadtb[CERT_PL_ATTR_VALIDFROMTIME]);
			expiresat = blobmsg_get_u64(payloadtb[CERT_PL_ATTR_EXPIRETIME]);

			if (certtype != CERTTYPE_AUTH) {
				ret = 2;
				DPRINTF("wrong certificate type\n");
				goto clean_and_return;
			}

			if (tv.tv_sec < validfrom ||
			    tv.tv_sec >= expiresat) {
				ret = 3;
				DPRINTF("certificate expired\n");
				goto clean_and_return;
			}

			snprintf(chainedpubkey, sizeof(chainedpubkey) - 1, "%s/%s", tmpdir, "chained-pubkey");
			write_file(chainedpubkey,
				   blobmsg_data(payloadtb[CERT_PL_ATTR_PUBKEY]),
				   blobmsg_data_len(payloadtb[CERT_PL_ATTR_PUBKEY]),
				   false);

			if (usign_f_pubkey(chainedfp, chainedpubkey, quiet)) {
				DPRINTF("cannot get fingerprint for chained key\n");
				ret = 2;
				goto clean_and_return;
			}
			if (pubkeydir && _usign_key_is_revoked(chainedfp, pubkeydir)) {
				DPRINTF("key %s has been revoked!\n", chainedfp);
				ret = 4;
				goto clean_and_return;
			}
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
				DPRINTF("stray trailing signature without anything to verify!\n");
				ret = 1;
			};
		}
	}

	if (checkmsg == -1)
		DPRINTF("missing signature to verify message!\n");

clean_and_return:
	if (chainedpubkey[0])
		unlink(chainedpubkey);
	rmdir(tmpdir);
	return ret | checkmsg;
}

#ifdef UCERT_FULL
/* dump single chain element to console */
static void cert_dump_blob(struct blob_attr *cert[CERT_ATTR_MAX]) {
	int i;
	char *json = NULL;

	for (i = 0; i < CERT_ATTR_MAX; i++) {
		struct blob_attr *v = cert[i];

		if (!v)
			continue;

		switch(cert_policy[i].type) {
		case BLOB_ATTR_BINARY:
			printf("signature:\n---\n%s---\n", (char *) blob_data(v));
			break;
		case BLOB_ATTR_NESTED:
			json = blobmsg_format_json_indent(blob_data(v), false, 0);
			if (!json) {
				DPRINTF("cannot parse payload\n");
				continue;
			}
			printf("payload:\n---\n%s\n---\n", json);
			free(json);
			break;
		}
	}
}

/* dump certfile to console */
static int cert_dump(const char *certfile) {
	struct cert_object *cobj;
	static LIST_HEAD(certchain);
	unsigned int count = 0;

	if (cert_load(certfile, &certchain)) {
		DPRINTF("cannot parse cert\n");
		return 1;
	}

	list_for_each_entry(cobj, &certchain, list) {
		printf("=== CHAIN ELEMENT %02u ===\n", ++count);
		cert_dump_blob(cobj->cert);
	}

	return 0;
}

/* issue an auth certificate for pubkey */
static int cert_issue(const char *certfile, const char *pubkeyfile, const char *seckeyfile) {
	struct blob_buf payloadbuf = {0};
	struct blob_buf certbuf = {0};
	struct timeval tv;
	ssize_t pklen, siglen;
	int revoker = 1;
	void *c;
	char pkb[512];
	char sigb[1024];
	char fname[256], sfname[256];
	char pkfp[17];
	char tmpdir[] = "/tmp/ucert-XXXXXX";

	pklen = read_file(pubkeyfile, pkb, sizeof(pkb) - 1, 32);
	if (pklen < 0) {
		if (!quiet)
			perror("Unable to load public key file");

		return -1;
	}

	pkb[pklen] = '\0';

	if (usign_f_pubkey(pkfp, pubkeyfile, quiet))
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

		siglen = read_file(sfname, sigb, sizeof(sigb) - 1, 1);
		if (siglen < 0) {
			if (!quiet)
				perror("Unable to load signature file");

			return 1;
		}

		sigb[siglen] = '\0';

		unlink(fname);
		unlink(sfname);

		blob_buf_init(&certbuf, 0);
		blob_put(&certbuf, CERT_ATTR_SIGNATURE, sigb, siglen);
		blob_put(&certbuf, CERT_ATTR_PAYLOAD, blob_data(payloadbuf.head), blob_len(payloadbuf.head));
		snprintf(fname, sizeof(fname) - 1, "%s%s", certfile, revoker?".revoke":"");
		write_file(fname, certbuf.head, blob_raw_len(certbuf.head), true);
		blob_buf_free(&certbuf);
		blob_buf_free(&payloadbuf);

		revoker--;
	}

	rmdir(tmpdir);

	return 0;
}
#endif

/* process revoker certificate */
static int cert_process_revoker(const char *certfile, const char *pubkeydir) {
	static LIST_HEAD(certchain);
	struct cert_object *cobj;
	struct blob_attr *containertb[CERT_CT_ATTR_MAX];
	struct blob_attr *payloadtb[CERT_PL_ATTR_MAX];
	struct stat st;
	struct timeval tv;
	time_t validfrom;
	enum certtype_id certtype;
	char *fingerprint;
	char rfname[512];

	int ret = -1;

	if (cert_load(certfile, &certchain)) {
		DPRINTF("cannot parse cert\n");
		return 1;
	}

	gettimeofday(&tv, NULL);

	list_for_each_entry(cobj, &certchain, list) {
		if (!cobj->cert[CERT_ATTR_PAYLOAD])
			return 2;

		/* blob has payload, verify that using signature */
		ret = cert_verify_blob(cobj->cert, NULL, pubkeydir);
		if (ret)
			return ret;

		blobmsg_parse(cert_cont_policy,
			      ARRAY_SIZE(cert_cont_policy),
			      containertb,
			      blob_data(cobj->cert[CERT_ATTR_PAYLOAD]),
			      blob_len(cobj->cert[CERT_ATTR_PAYLOAD]));
		if (!containertb[CERT_CT_ATTR_PAYLOAD]) {
			DPRINTF("no ucert in signed payload\n");
			return 2;
		}

		blobmsg_parse(cert_payload_policy,
			      ARRAY_SIZE(cert_payload_policy),
			      payloadtb,
			      blobmsg_data(containertb[CERT_CT_ATTR_PAYLOAD]),
			      blobmsg_data_len(containertb[CERT_CT_ATTR_PAYLOAD]));

		if (!payloadtb[CERT_PL_ATTR_CERTTYPE] ||
		    !payloadtb[CERT_PL_ATTR_VALIDFROMTIME] ||
		    !payloadtb[CERT_PL_ATTR_KEY_FINGERPRINT]) {
			DPRINTF("missing mandatory ucert attributes\n");
			return 2;
		}

		certtype = blobmsg_get_u32(payloadtb[CERT_PL_ATTR_CERTTYPE]);
		validfrom = blobmsg_get_u64(payloadtb[CERT_PL_ATTR_VALIDFROMTIME]);
		fingerprint = blobmsg_get_string(payloadtb[CERT_PL_ATTR_KEY_FINGERPRINT]);

		if (certtype != CERTTYPE_REVOKE) {
			DPRINTF("wrong certificate type\n");
			return 2;
		}

		if (tv.tv_sec < validfrom) {
			return 3;
		}

		snprintf(rfname, sizeof(rfname)-1, "%s/%s", pubkeydir, fingerprint);
		/* check if entry in pubkeydir exists */
		if (stat(rfname, &st) == 0) {
			if (_usign_key_is_revoked(fingerprint, pubkeydir)) {
				DPRINTF("existing revoker deadlink for key %s\n", fingerprint);
				continue;
			};

			/* remove any other entry */
			if (unlink(rfname))
				return -1;
		}

		ret = symlink(".revoked.", rfname);
		if (ret)
			return ret;

		DPRINTF("created revoker deadlink for key %s\n", fingerprint);
	};

	return ret;
}

/* load and verify certfile (and message) */
static int cert_verify(const char *certfile, const char *pubkeyfile, const char *pubkeydir, const char *msgfile) {
	static LIST_HEAD(certchain);

	if (cert_load(certfile, &certchain)) {
		DPRINTF("cannot parse cert\n");
		return 1;
	}

	return chain_verify(msgfile, pubkeyfile, pubkeydir, &certchain);
}

/* output help */
static int usage(const char *cmd)
{
#ifndef UCERT_STRIP_MESSAGES
	fprintf(stderr,
		"Usage: %s <command> <options>\n"
		"Commands:\n"
#ifdef UCERT_FULL
		"  -A:			append signature (needs -c and -x)\n"
		"  -D:			dump (needs -c)\n"
		"  -I:			issue cert and revoker (needs -c and -p and -s)\n"
#endif /* UCERT_FULL */
		"  -R:			process revoker certificate (needs -c and -P)\n"
		"  -V:			verify (needs -c and -p|-P, may have -m)\n"
		"Options:\n"
		"  -c <file>:		certificate file\n"
		"  -m <file>:		message file (verify only)\n"
		"  -p <file>:		public key file\n"
		"  -P <path>:		public key directory (verify only)\n"
		"  -q:			quiet (do not print verification result, use return code only)\n"
#ifdef UCERT_FULL
		"  -s <file>:		secret key file (issue only)\n"
		"  -x <file>:		signature file (append only)\n"
#endif /* UCERT_FULL */
		"\n",
		cmd);
#endif /* UCERT_STRIP_MESSAGES */
	return 1;
}

/* parse command line options and call functions */
int main(int argc, char *argv[]) {
	int ch;
	const char *msgfile = NULL;
	const char *pubkeyfile = NULL;
	const char *pubkeydir = NULL;
	const char *certfile = NULL;
#ifdef UCERT_FULL
	const char *sigfile = NULL;
	const char *seckeyfile = NULL;
#endif

	quiet = false;
	while ((ch = getopt(argc, argv,
		"RVc:m:p:P:q"
#ifdef UCERT_FULL
		"ADIs:x:"
#endif
	       )) != -1) {
		switch (ch) {
#ifdef UCERT_FULL
		case 'A':
			if (cmd != CMD_NONE)
				return usage(argv[0]);
			cmd = CMD_APPEND;
			break;
		case 'D':
			if (cmd != CMD_NONE)
				return usage(argv[0]);
			cmd = CMD_DUMP;
			break;
		case 'I':
			if (cmd != CMD_NONE)
				return usage(argv[0]);
			cmd = CMD_ISSUE;
			break;
#endif
		case 'R':
			if (cmd != CMD_NONE)
				return usage(argv[0]);
			cmd = CMD_REVOKE;
			break;
		case 'V':
			if (cmd != CMD_NONE)
				return usage(argv[0]);
			cmd = CMD_VERIFY;
			break;
		case 'c':
			if (certfile || cmd == CMD_NONE)
				return usage(argv[0]);
			certfile = optarg;
			break;
		case 'm':
			if (msgfile || cmd != CMD_VERIFY)
				return usage(argv[0]);
			msgfile = optarg;
			break;
		case 'p':
			if (pubkeyfile || (cmd != CMD_VERIFY && cmd != CMD_ISSUE) || cmd == CMD_NONE)
				return usage(argv[0]);
			pubkeyfile = optarg;
			break;
		case 'P':
			if (pubkeydir || (cmd != CMD_VERIFY && cmd != CMD_REVOKE) || cmd == CMD_NONE)
				return usage(argv[0]);
			pubkeydir = optarg;
			break;
		case 'q':
			if (quiet)
				return usage(argv[0]);
			quiet = true;
			break;
#ifdef UCERT_FULL
		case 's':
			if (seckeyfile || cmd != CMD_ISSUE || cmd == CMD_NONE)
				return usage(argv[0]);
			seckeyfile = optarg;
			break;
		case 'x':
			if (sigfile || cmd != CMD_APPEND || cmd == CMD_NONE)
				return usage(argv[0]);
			sigfile = optarg;
			break;
#endif
		default:
			return usage(argv[0]);
		}
	}

	switch (cmd) {
#ifdef UCERT_FULL
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
#endif
	case CMD_REVOKE:
		if (certfile && pubkeydir)
			return cert_process_revoker(certfile, pubkeydir);
		else
			return usage(argv[0]);
	case CMD_VERIFY:
		if (certfile && (pubkeyfile || pubkeydir))
			return cert_verify(certfile, pubkeyfile, pubkeydir, msgfile);
		else
			return usage(argv[0]);
	default:
		return usage(argv[0]);
	}

	/* unreachable */
	return usage(argv[0]);
}
