Dependencies
- libpam-python

Utilities
- pamtester

See also
- https://pam-python.sourceforge.net/
- https://www.youtube.com/watch?v=GfyM8lFkjo8 t108 Ball and Chain A New Paradigm in Stored Password Security Benjamin Donnelly and Tim Tomes
- https://www.youtube.com/watch?v=UHjGEawvDZs Ball and Chain - A New Paradigm in Stored Password Security

Example defaults file:

ball: /etc/security/ball-and-chain.ball
pointer-bits: 64 # this can be 32 for I (unsigned int) or L (unsigned long) both of which are standard size 4 or 64 for Q (unsigned long long) which is standard size 8
pointer-data-pairs: 4
data-length: 4
data-hash: SHA256
password-hash: SHA256
cipher: AES256

password-hash must be one of:
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- SHA512_224
- SHA512_256
- SHA3_224
- SHA3_256
- SHA3_384
- SHA3_512
data-hash must be one of:
- SHA256
cipher must be one of:
- AES256

If the output of password-hash is longer than the required key size of the cipher, it will be truncated to the required size
If the output of password-hash is shorter than the required key size of the cipher, it will be padded (with zeroes) to the required size

See also
- https://docs.python.org/3/library/struct.html
- https://docs.python.org/3/library/hashlib.html
- https://docs.python.org/3/library/secrets.html
- https://cryptography.io
- https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
- https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
- https://www.chiark.greenend.org.uk/doc/libpam-doc/html/Linux-PAM_MWG.html
- https://pam-python.sourceforge.net/
- https://pam-python.sourceforge.net/doc/html/
- https://github.com/sunweaver/pam-python/
- https://pubs.opengroup.org/onlinepubs/8329799/toc.htm
