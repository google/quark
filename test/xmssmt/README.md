# XMSS/XMSS-MT Verification Test Apps
Various apps to test XMSS/XMSS-MT signature verification

* ```README.txt``` - This file.
* ```quark_misc.c/h``` - Miscellaneous functions related to debugging during
development.  Note that these functions are intended to be used in a release candidate.  They are included only
in the interest of completeness.
* ```xmssmt_verify.c/h``` - Primary XMSS/XMSS-MT verification code that handles all of
the main functions required to perform XMSS/XMSS-MT.  The header file in particular is where you will find all interesting
definitions and data types.
* ```xmssmt_test.c``` - A primitive command-line utility that you can use to
perform one-off signature verifications using a simple interface. I used this for verification purposes so it isn't documented
to the same degree as the above library files/functions.
* ```xmssmt_kat.c``` - A primitive known-answer-test utility that you can use to
test the verification primitive works with a set of known
good vectors for sanity testing purposes.  I also made use
of thise for HW platform testing and analytics.
* ```xmss_ref_*.h``` - XMSS reference vector sets for the KAT utility where the
titles indicate the total # of signatures they provide
(e.g., xmss_ref_20.h provides a total signature space of
2^20 signatures).
* ```xmssmt_ref_*.h``` - XMSS-MT reference vector sets for the KAT utility where the
titles indicate the total # of signatures they provide, as well as the number of subtrees in their hierarchy (i.e.,
xmssmt_ref_60_6.h contains a signature generated using a 6-level tree, each of which contains 60/6 = 10 levels,
for a total signature space of 2^60 signatures).
* ```xmss_ref_001.h``` - Another set of XMSS reference vectors, but this one had
intermediate values I used for debugging purposes.
* ```xmssmt_ref_001.h``` - Another set of XMSS-MT reference vectors, but this one had
intermediate values I used for debugging purposes.
* ```Doxyfile``` - Basic default doxygen configuration file which will
generate a C-targeted documentation file set under the doc/ subdirectory.  All of the source files, except for
the simple demo.c/kat.c/test.c utilities, are formatted to be doxygen-compatible.
* ```.gitignore``` - Basic git ignore file I used which you can throw away if
you so desire.
* ```Makefile``` - Very simple make file that will build the various parts
of the project.
* ```test_sigs.pl``` - Another Perl script utility that
lets you run batch verification tests in conjunction with
* ```xmss-reference-quark's``` - ui/*.pl scripts.  Check out those files' comments for details.
