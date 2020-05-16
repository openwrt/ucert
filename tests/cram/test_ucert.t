check that ucert is producing expected results:

  $ [ -n "$TEST_BIN_DIR" ] && export PATH="$TEST_BIN_DIR:$PATH"
  $ export TEST_INPUTS="$TESTDIR/inputs"
  $ alias ucert='valgrind --quiet --leak-check=full ucert'

  $ ucert
  Usage: ucert <command> <options>
  Commands:
    -A:\t\t\tappend signature (needs -c and -x) (esc)
    -D:\t\t\tdump (needs -c) (esc)
    -I:\t\t\tissue cert and revoker (needs -c and -p and -s) (esc)
    -R:\t\t\tprocess revoker certificate (needs -c and -P) (esc)
    -V:\t\t\tverify (needs -c and -p|-P, may have -m) (esc)
  Options:
    -c <file>:\t\tcertificate file (esc)
    -m <file>:\t\tmessage file (verify only) (esc)
    -p <file>:\t\tpublic key file (esc)
    -P <path>:\t\tpublic key directory (verify only) (esc)
    -q:\t\t\tquiet (do not print verification result, use return code only) (esc)
    -s <file>:\t\tsecret key file (issue only) (esc)
    -x <file>:\t\tsignature file (append only) (esc)
  
  [1]

  $ ucert -D -c $TEST_INPUTS/key-build.ucert
  === CHAIN ELEMENT 01 ===
  signature:
  ---
  untrusted comment: signed by key 84bfc88a17166577
  RWSEv8iKFxZld+bQ+NTqCdDlHOuVYNw5Qw7Q8shjfMgFJcTqrzaqO0bysjIQhTadmcwvWiWvHlyMcwAXSix2BYdfghz/zhDjvgU=
  ---
  payload:
  ---
  "ucert": {
  \t"certtype": 1, (esc)
  \t"validfrom": 1546188410, (esc)
  \t"expiresat": 1577724410, (esc)
  \t"pubkey": "untrusted comment: Local build key\\nRWSEv8iKFxZld6vicE1icWhYNfEV9PM7C9MKUKl+YNEKB+PdAWGDF5Z9\\n" (esc)
  }
  ---
  $ ucert-san -D -c $TEST_INPUTS/key-build.ucert
  === CHAIN ELEMENT 01 ===
  signature:
  ---
  untrusted comment: signed by key 84bfc88a17166577
  RWSEv8iKFxZld+bQ+NTqCdDlHOuVYNw5Qw7Q8shjfMgFJcTqrzaqO0bysjIQhTadmcwvWiWvHlyMcwAXSix2BYdfghz/zhDjvgU=
  ---
  payload:
  ---
  "ucert": {
  \t"certtype": 1, (esc)
  \t"validfrom": 1546188410, (esc)
  \t"expiresat": 1577724410, (esc)
  \t"pubkey": "untrusted comment: Local build key\\nRWSEv8iKFxZld6vicE1icWhYNfEV9PM7C9MKUKl+YNEKB+PdAWGDF5Z9\\n" (esc)
  }
  ---

  $ ucert -D -c $TEST_INPUTS/invalid.ucert
  cert_dump: cannot parse cert
  [1]

  $ ucert-san -D -c $TEST_INPUTS/invalid.ucert
  cert_dump: cannot parse cert
  [1]
