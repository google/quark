# Quark Common Files
Files common to both ```hss_verify``` and ```xmssmt_verify```

* ```README.md``` - This file.
* ```endian_utils.c/h``` - Functions related to reading/writing big endian values
* ```hash_wrappers.c/h``` - Functions related to hashing
* ```sha256.c/h``` - Functions related to the SHA256 hashing function
* ```sha256asm.s``` - Optimized ARM assembly language implementation of SHA256

## Using Optimized SHA256 Implementation:

You can enable the use of an optimized ARM assembly language implementation of SHA256 by undefining the QUARK_USE_SHA256_C flag in quark_sha256.c.  This will swap out the C-based compression function for an optimized ASM version.

The scratch buffer is used to deal with the lack of dynamic allocation within functions.