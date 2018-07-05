# HSS Verification Test Apps
Various apps to test HSS signature verification

 * ```README.md``` - This file.
 * ```quark_misc.c/h``` --- Miscellaneous functions related to debugging during development.  Note that these functions are intended to be used in a release candidate.  They are included only in the interest of completeness.
 * ```hss_demo.c``` - A primitive command-line utility that you can use to perform one-off signature verifications using an interface similar to that provided in the hash-sigs-quark library. I used this for verification purposes so it isn't documented to the same degree as the above library files/functions.
 * ```hss_kat.c``` - A primitive known-answer-test utility that you can use to test the verification primitive works with a set of known good vectors for sanity testing purposes.  I also made use of thise for HW platform testing and analytics.
 * ```hss_test.c``` - A basic test program that was intended to exercise all of the various failure paths through the code to ensure the expected conditions were caught and handled by tnhe code. This is still a work in progress so caveat emptor!
 * ```hss_ref_*.h``` - Reference vector sets for the KAT utility.  They were chosen to mirror the XMSS-MT reference configs so their titles indicate the total # of signatures they provide, as well as the number of subtrees in their hierachy (i.e., hss_ref_60_6.h contains a signature generated using a 6-level tree, each of which contains 60/6 = 10 levels, for a total signature space of 2^60 signatures).
 * ```hss_vectors_001.h``` - Another set of reference vectors, but this one had intermediate values I used for debugging purposes.
 * ```.gitignore``` - Basic git ignore file I used which you can throw away if you so desire.
 * ```Makefile``` - Very simple make file that will build the various parts of the project.
 * ```gen_header.pl``` - Perl script (don't judge me!) utility that allows you to generate new KAT's by converting a {sig, key, msg} file set into a C-compatible header file.  Check out the file's comments for details.
 * ```test_sigs.pl``` - Another Perl script (seeing a trend here?) utility that lets you run batch verification tests in conjunction with hash-sigs-quark's gensigs.pl script.  Check out the file's comments for details.