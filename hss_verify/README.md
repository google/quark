# HSS Verification Library
This directory contains all of the necessary files to build an HSS signature verification primitive using a generic GNU Makefile-based build chain.

 * ```README.md``` - This file.
 * ```quark_misc.c/h``` --- Miscellaneous functions related to debugging during development.  Note that these functions are intended to be used in a release candidate.  They are included only in the interest of completeness.
 * ```quark_verify.c/h``` - Primary HSS verification code that handles all of the main functions required to perform HSS.  The header file in particular is where you will find all interesting definitions and data types.
 * ```demo.c``` - A primitive command-line utility that you can use to perform one-off signature verifications using an interface similar to that provided in the hash-sigs-quark library. I used this for verification purposes so it isn't documented to the same degree as the above library files/functions.
 * ```kat.c``` - A primitive known-answer-test utility that you can use to test the verification primitive works with a set of known good vectors for sanity testing purposes.  I also made use of thise for HW platform testing and analytics.
 * ```test.c``` - A basic test program that was intended to exercise all of the various failure paths through the code to ensure the expected conditions were caught and handled by tnhe code. This is still a work in progress so caveat emptor!
 * ```hss_ref_*.h``` - Reference vector sets for the KAT utility.  They were chosen to mirror the XMSS-MT reference configs so their titles indicate the total # of signatures they provide, as well as the number of subtrees in their hierachy (i.e., hss_ref_60_6.h contains a signature generated using a 6-level tree, each of which contains 60/6 = 10 levels, for a total signature space of 2^60 signatures).
 * ```hss_vectors_001.h``` - Another set of reference vectors, but this one had intermediate values I used for debugging purposes.
 * ```Doxyfile``` - Basic default doxygen configuration file which will generate a C-targeted documentation file set under the doc/ subdirectory.  All of the source files, except for the simple demo.c/kat.c/test.c utilities, are formatted to be doxygen-compatible.
 * ```.gitignore``` - Basic git ignore file I used which you can throw away if you so desire.
 * ```Makefile``` - Very simple make file that will build the various parts of the project.
 * ```gen_header.pl``` - Perl script (don't judge me!) utility that allows you to generate new KAT's by converting a {sig, key, msg} file set into a C-compatible header file.  Check out the file's comments for details.
 * ```test_sigs.pl``` - Another Perl script (seeing a trend here?) utility that lets you run batch verification tests in conjunction with hash-sigs-quark's gensigs.pl script.  Check out the file's comments for details.

## Flash/Cache/Scratch Details:

The emulated flash interface causes a bit of grief in terms of us designing to
something we don't actually have.  As such the code is a bit odd and perhaps not
structured in an optimal way, so allow me to take a minute to explain my approach.
First off, you'll notice a number of functions of the form "<*>Flash( )", which
basically are the emulated flash versions of memory-based functions (e.g.,
hssVerifySignatureFlash( ) is an emulated flash version of hssVerifySignature( )).
These emulated flash variants differ from their memory-based counterparts only
in that they expect the signature to be passed in as an offset value, and they
require a scratch buffer to be passed in as well (note that this scratch buffer
is a separate from any flash cache that may be defined... but more on that later).
Check out quark_verify.c and quark_verify.h for examples of the two, it should
(hopefully!) be pretty obvious what the distinctions are, and I tried to be
consistent wherever they appear.

The "FLASH" is emulated using a global array g_flashBuff[] defined in quark_verify.h,
and you can see an example of use dummying this out in kat.c where we basically
read the signature from the header file and then memcpy it into g_flashBuff[]
at a given offset, which is what we pass in to hssVerifySignatureFlash( ).  Any
accesses to the flash are ultimately passed through the nlflash_read( ) dummy
call defined in quark_verify.c which does a memcpy out of g_flashBuff[] using the
offset it's given.  The call to nlflash_read( ) is in turn abstracted away via
the function flashcpy( ) which was my lame attempt to emulate the memcpy( )
function while adding some simple error checking (e.g., if you were able to read
the number of bytes you were expecting).  The intent was to make it simple to
drop in the emulated flash interface by just swapping out memcpy( ) operations
for flashcpy( ) operations when accessing the signature vector which is too
large to fit in RAM.

Given the penalties associated with flash access (i.e., 10ms access + 1us per
byte to read data), it became apparent that we needed to coalesce flash accesses
to try and avoid the 10ms access penalty.  To this end we introduced a flash
cache (g_cache[] defined in quark_verify.c along with its state variables) which
we use to pre-fetch blocks of flash data into a RAM buffer.  We went with a
very simple caching strategy where we track the portion of the flash we are
currently storing in the cache and then compare future flash access requests
against this region to see if it falls within it (i.e., is completely contained
within the cache).  If it is then we just memcpy( ) from the cache to its
destination, if not then we initiate a new flash access to refill the cache
with the flash region starting at the requested offset.  The intent was to keep
things very simple so we didn't investigate any more elaborate replacement
strategies.  I will provide some simple performance analysis that I did with
regards to our implementation using this approach for various sizes of caching.
The caching is enabled via the QUARK_USE_FLASH_CACHE flag defined in quark_verify.h
(along with QUARK_CACHE_SIZE which defines the size of the g_cache[] array).
When this flag is defined it will define a variant of flashcpy( ) called
flashcpy_cached( ) which implements the aforementioned caching behaviour, and
which is a drop-in replacement for flashcpy( ).  I've left both in so that
you can play with it to see how things actually work on the final HW platform.
I was not able to test this out on the HW platform I have so I'm happy to
support you in any way that I can going forward to get this working.  Just let
me know what I can do to help!

As mentioned before, the scratch buffer is separate from the flash cache, and
its minimum size is currently defined in quark_verify.h via QUARK_SCRATCH_SIZE.
You will need to allocate that buffer and pass it (and its length) into the
top level signature verification primitive if you're using the <*>Flash( )
variants.

All of the above functionality can be observed in the kat.c utility where you
have examples of how to configure and setup the various options related to
flash, caching, and scratch buffers.

## Documentation:

All of the source code (minus the utilitites) is formatted to be Doxygen-compatible
so you should be able to generate a documentation package using the given basic
Doxyfile configuration which will generate the documentation tree under the doc/
subdirectory.

## Building the Code:

I used a very simple GCC Makefile-based build chain for development on Ubuntu 16.04.3,
and then eventually migrated that onto the Nucleo64-STM32L152RE hardware platform using
STM's System Workbench for STM32 which is an Eclipse-based IDE that utilizes GNU's
ARM cross-compilation toolchain.  I'll include archives of the resulting projects that
I ran on the hardware platform, the only real difference in the source files for the
HW projects were the change of standard library includes to use " " instead of < >
(e.g., #include <stdlib.h> --> #include "stdlib.h").

## Using Optimized SHA256 Implementation:

You can enable the use of an optimized ARM assembly language implementation of SHA256
by undefining the QUARK_USE_SHA256_C flag in quark_sha256.c.  This will swap out the
C-based compression function for an optimized ASM version.  I will be interested in
seeing how much benefit this provides in the final version as I'm only seeing modest
gains on my Nucleo64 platform (about 13%).  I expected to see more so I'll continue
to investigate on that front.
The scratch buffer is used to deal with the lack of dynamic allocation within
functions.  

## Static Functions:

Note that at this point almost nothing has been declared static as I wanted to
be able to access functions for testing purposes.  I assume that you will want
to go through and "static"-ize functions as you decide what level of capability
you ultimately want exposed externally.  The decision is yours!
