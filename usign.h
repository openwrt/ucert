int usign_v(const char *msgfile, const char *pubkeyfile,
	    const char *pubkeydir, const char *sigfile, bool quiet);

int usign_s(const char *msgfile, const char *seckeyfile, const char *sigfile, bool quiet);

int usign_f_pubkey(char *fingerprint, const char *pubkeyfile);

int usign_f_seckey(char *fingerprint, const char *seckeyfile);

int usign_f_sig(char *fingerprint, const char *sigfile);
