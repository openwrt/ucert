#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "usign.h"

int usign_s(const char *msgfile, const char *seckeyfile, const char *sigfile, bool quiet) {
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;

	usign_argv[usign_argc++] = "/usr/bin/usign";
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
		if (execv(usign_argv[0], usign_argv))
			return -1;

		break;

	default:
		waitpid(pid, &status, 0);
		return WEXITSTATUS(status);
	}

	return -1;
}

static int usign_f(char *fingerprint, const char *pubkeyfile, const char *seckeyfile, const char *sigfile) {
	int fds[2];
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;

	if (pipe(fds))
		return -1;

	usign_argv[usign_argc++] = "/usr/bin/usign";
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

		close(0);
		close(2);
		close(fds[0]);
		close(fds[1]);

		if (execv(usign_argv[0], usign_argv))
			return -1;

		break;

	default:
		waitpid(pid, &status, 0);
		if (fingerprint && !WEXITSTATUS(status)) {
			memset(fingerprint, 0, 16);
			read(fds[0], fingerprint, 16);
			fingerprint[16] = '\0';
		}
		close(fds[0]);
		close(fds[1]);
		return WEXITSTATUS(status);
	}

	return -1;
}

int usign_f_pubkey(char *fingerprint, const char *pubkeyfile) {
	return usign_f(fingerprint, pubkeyfile, NULL, NULL);
}

int usign_f_seckey(char *fingerprint, const char *seckeyfile) {
	return usign_f(fingerprint, NULL, seckeyfile, NULL);
}

int usign_f_sig(char *fingerprint, const char *sigfile) {
	return usign_f(fingerprint, NULL, NULL, sigfile);
}

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

int usign_v(const char *msgfile, const char *pubkeyfile,
	    const char *pubkeydir, const char *sigfile, bool quiet) {
	pid_t pid;
	int status;
	const char *usign_argv[16] = {0};
	unsigned int usign_argc = 0;
	char fingerprint[17];

	if (usign_f_sig(fingerprint, sigfile))
		return 1;

	if (pubkeydir && _usign_key_is_revoked(fingerprint, pubkeydir))
		return 1;

	usign_argv[usign_argc++] = "/usr/bin/usign";
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
		if (execv(usign_argv[0], usign_argv))
			return -1;

		break;

	default:
		waitpid(pid, &status, 0);
		return WEXITSTATUS(status);
	}

	return -1;
}
