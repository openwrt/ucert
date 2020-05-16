/*
 * wrapper functions around the usign executable
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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "usign.h"

#ifdef UCERT_HOST_BUILD
#define USIGN_EXEC "usign"
#else
#define USIGN_EXEC "/usr/bin/usign"
#endif

/*
 * check for revoker deadlink in pubkeydir
 * return true if a revoker exists, false otherwise
 */
int _usign_key_is_revoked(const char *fingerprint, const char *pubkeydir) {
	char tml[64] = {0};
	char rfname[256] = {0};

	snprintf(rfname, sizeof(rfname)-1, "%s/%s", pubkeydir, fingerprint);
	if (readlink(rfname, tml, sizeof(tml)) > 0 &&
	    !strcmp(tml, ".revoked.")) {
		return true;
	};

	return false;
}

#ifdef UCERT_FULL
/*
 * call usign -S ...
 * return WEXITSTATUS or -1 if fork fails
 */
int usign_s(const char *msgfile, const char *seckeyfile, const char *sigfile, bool quiet) {
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;

	usign_argv[usign_argc++] = USIGN_EXEC;
	usign_argv[usign_argc++] = "-S";
	usign_argv[usign_argc++] = "-m";
	usign_argv[usign_argc++] = msgfile;
	usign_argv[usign_argc++] = "-s";
	usign_argv[usign_argc++] = seckeyfile;
	usign_argv[usign_argc++] = "-x";
	usign_argv[usign_argc++] = sigfile;

	if (quiet)
		usign_argv[usign_argc++] = "-q";

	pid = fork();
	switch (pid) {
	case -1:
		return -1;

	case 0:
		execvp(usign_argv[0], (char *const *)usign_argv);
		if (!quiet)
			perror("Failed to execute usign");
		_exit(1);
	}

	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#else
int usign_s(const char *msgfile, const char *seckeyfile, const char *sigfile, bool quiet) {
	return -1;
};
#endif

/*
 * call usign -F ... and set fingerprint returned
 * return WEXITSTATUS or -1 if fork fails
 */
static int usign_f(char fingerprint[17], const char *pubkeyfile, const char *seckeyfile, const char *sigfile, bool quiet) {
	int fds[2];
	FILE *f;
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;

	if (pipe(fds))
		return -1;

	usign_argv[usign_argc++] = USIGN_EXEC;
	usign_argv[usign_argc++] = "-F";

	if (pubkeyfile) {
		usign_argv[usign_argc++] = "-p";
		usign_argv[usign_argc++] = pubkeyfile;
	}

	if (seckeyfile) {
		usign_argv[usign_argc++] = "-s";
		usign_argv[usign_argc++] = seckeyfile;
	}

	if (sigfile) {
		usign_argv[usign_argc++] = "-x";
		usign_argv[usign_argc++] = sigfile;
	}

	pid = fork();
	switch (pid) {
	case -1:
		return -1;

	case 0:
		dup2(fds[1], 1);

		close(fds[0]);
		close(fds[1]);

		execvp(usign_argv[0], (char *const *)usign_argv);
		if (!quiet)
			perror("Failed to execute usign");
		_exit(1);
	}

	close(fds[1]);

	waitpid(pid, &status, 0);
	status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

	if (!fingerprint || status) {
		close(fds[0]);
		return status;
	}

	f = fdopen(fds[0], "r");
	if (fread(fingerprint, 1, 16, f) != 16)
		status = -1;
	fclose(f);
	if (status)
		return status;

	fingerprint[16] = '\0';
	if (strspn(fingerprint, "0123456789abcdefABCDEF") != 16)
		status = -1;

	return status;
}

/*
 * call usign -F -p ...
 */
int usign_f_pubkey(char fingerprint[17], const char *pubkeyfile, bool quiet) {
	return usign_f(fingerprint, pubkeyfile, NULL, NULL, quiet);
}

/*
 * call usign -F -s ...
 */
int usign_f_seckey(char fingerprint[17], const char *seckeyfile, bool quiet) {
	return usign_f(fingerprint, NULL, seckeyfile, NULL, quiet);
}

/*
 * call usign -F -x ...
 */
int usign_f_sig(char fingerprint[17], const char *sigfile, bool quiet) {
	return usign_f(fingerprint, NULL, NULL, sigfile, quiet);
}


/*
 * call usign -V ...
 * return WEXITSTATUS or -1 if fork fails
 */
int usign_v(const char *msgfile, const char *pubkeyfile,
	    const char *pubkeydir, const char *sigfile, bool quiet) {
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;
	char fingerprint[17];

	if (usign_f_sig(fingerprint, sigfile, quiet)) {
		if (!quiet)
			fprintf(stderr, "cannot get signing key fingerprint\n");
		return 1;
	}

	if (pubkeydir && _usign_key_is_revoked(fingerprint, pubkeydir)) {
		if (!quiet)
			fprintf(stderr, "key %s has been revoked!\n", fingerprint);
		return 1;
	}
	usign_argv[usign_argc++] = USIGN_EXEC;
	usign_argv[usign_argc++] = "-V";
	usign_argv[usign_argc++] = "-m";
	usign_argv[usign_argc++] = msgfile;

	if (quiet)
		usign_argv[usign_argc++] = "-q";

	if (pubkeyfile) {
		usign_argv[usign_argc++] = "-p";
		usign_argv[usign_argc++] = pubkeyfile;
	}

	if (pubkeydir) {
		usign_argv[usign_argc++] = "-P";
		usign_argv[usign_argc++] = pubkeydir;
	}

	if (sigfile) {
		usign_argv[usign_argc++] = "-x";
		usign_argv[usign_argc++] = sigfile;
	}

	pid = fork();
	switch (pid) {
	case -1:
		return -1;

	case 0:
		execvp(usign_argv[0], (char *const *)usign_argv);
		if (!quiet)
			perror("Failed to execute usign");
		_exit(1);
	}

	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
