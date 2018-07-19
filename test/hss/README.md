# HSS Verification Test Apps
Various apps to test HSS signature verification

 * ```README.md``` - This file.
 * ```CMakeLists.txt``` - CMake configuration file for generating Makefile(s).
 * ```quark_misc.c/h``` - Miscellaneous functions related to debugging during development.  Note that these functions are intended to be used in a release candidate.  They are included only in the interest of completeness.
 * ```demo.c``` - A primitive command-line utility that can be used to perform one-off signature verifications.
 * ```kat.c``` - A primitive known-answer-test utility that can be used to test that the HSS verification primitives work with a set of known good vectors for sanity testing purposes.
 * ```test.c``` - A basic test that exercises various execution paths for all of the reference vector sets found in the `hss_ref_*.h` files.
 * ```hss_ref_*.h``` - Reference vector sets for the KAT utility.  They were chosen to mirror the XMSS-MT reference configs so their titles indicate the total # of signatures they provide, as well as the number of subtrees in their hierachy (i.e., `hss_ref_60_6.h` contains a signature generated using a 6-level tree, each of which contains 60/6 = 10 levels, for a total signature space of 2<sup>60</sup> signatures). These files were all generated using the [HSS reference implementation available on Github](https://github.com/cisco/hash-sigs "HSS reference repo").
 * ```hss_vectors_001.h``` - Another set of reference vectors, but this one includes intermediate values that can be used for debugging purposes. These files were all generated using the [HSS reference implementation available on Github](https://github.com/cisco/hash-sigs "HSS reference repo").
 * ```Makefile``` - Very simple make file that will build the various parts of the project.
 * ```test_sigs.pl``` - A Perl script utility that performs batch verification tests in conjunction with reference files found in the Vectors subdirectory.  Check out the script's comments for details.
 * ```/Vectors``` - Subdirectory containing a large variety of reference signatures/keys/files that are used by the `test_sigs.pl` script to perform batch validation of the HSS signature verification primitives. All of the vectors within this subdirectory were generated using the [HSS reference implementation available on Github](https://github.com/cisco/hash-sigs "HSS reference repo").
