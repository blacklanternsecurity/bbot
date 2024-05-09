import ssl

ssl_context_noverify = ssl.create_default_context()
ssl_context_noverify.check_hostname = False
ssl_context_noverify.verify_mode = ssl.CERT_NONE
ssl_context_noverify.options &= ~ssl.OP_NO_SSLv2 & ~ssl.OP_NO_SSLv3
ssl_context_noverify.set_ciphers("ALL:@SECLEVEL=0")
ssl_context_noverify.options |= 0x4  # Add the OP_LEGACY_SERVER_CONNECT option
