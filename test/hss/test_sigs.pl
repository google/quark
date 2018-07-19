#!/usr/bin/perl
#============================================================================
#
# Copyright 2018 Google LLC
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# */
#================================================================================
# test_sigs.pl - automated signature verification batch script
#
#   This script scans <$dir> to find a list of all HSS public key files
#   (<@files>) and then uses these to search for corresponding signature
#   files (<@sigFiles>).  It then attempts to verify the generated signatures
#   and tracks the resulting pass/fail stats that it prints onscreen at
#   completion.
#
#   Public key files are identified by their file name formats which are
#   expected to be of the form:
#
#        hss_<h0>.<w0>[_<hi>.<wi>]*.pub
#
#   where there can be 0 to 7 _<hi>.<wi> terms depending on
#   the L value (0 for L = 1, 7 for L = 8).  The <hi> terms correspond
#   to the tree height of that level, whereas <wi> corresponds to the
#   Witnernitz parameter used for that level.  The values are given in
#   top-down order (e.g., hss_10.2_20.4_30.8.pub corresponds to the
#   public key of an HSS with three layers, the top-most layer being a
#   tree of depth 10 that uses Winternitz = 2, the middle layer being a
#   tree of depth 20 that uses Winternitz = 4, and the bottom layer being
#   a tree of depth 30 that uses Winternitz = 8).
#
#   The corresponding signature files are identified by their file name
#   formats which are expected to be of the form:
#
#        hss_<h0>.<w0>[_<hi>.<wi>]*_<#>.sig
#
#   where <#> is an integer value ranging from 0 onwards used to uniquify
#   the signature files when multiple signatures are generated for a given
#   HSS key value.
#
#   The signed file is identified by its file name format which is expected
#   to be of the form:
#
#        hss_<h0>.<w0>[_<hi>.<wi>]*
#
#   The verification primitive is specified via <$hssVerify>.
#
#================================================================================
use strict;
use warnings;

#================================================================================
# Variables
#================================================================================
my $hssVerify = "demo"; # Verification primitive for HSS signatures
my $command;            # Will contain the command line we execute
my $ret;                # Will capture stdout of command line executed
my $numTests = 0;       # Total number of signature verifications that we've performed
my $passCnt = 0;        # Number of signature verification checks that have passed
my $failCnt = 0;        # Number of signature verification checks that have failed
my @pubFiles;           # Array containing list of public key files
my $pubFile;            # Iterator that we use to walk through @files
my @sigFiles;           # Array containing list of signature files
my $sigFile;            # Iterator that we use to walk through @sigFiles
my $msgFile;            # Message filename

# Directory where we'll be looking for signatures, public keys, signed files
my $dir = "./Vectors";

#================================================================================
# Program
#================================================================================
# No sense doing anything if no verification primitive is present
if (-e $hssVerify) {
    # Attempt to open the source directory where we'll find the files we need to
    # perform the signature verifications
    opendir(DIR, $dir)
        or die("ERROR: unable to open $dir, aborting: $!");

    # Get list of all HSS public key files in the given directory
    @pubFiles = grep (/^hss_.*\.pub$/, readdir(DIR) );

    # Iterate through the list of public key files to see which we can use to
    # perform signature verification tests
    foreach $pubFile (@pubFiles) {
        # Get the stem filename and check that the corresponding signed file
        # exists before attempting to do any signature verification tests
        $pubFile =~ m/(.*)\.pub$/;
        $msgFile = $1;
        if (-e "$dir/$msgFile") {
            print("Validating signatures for $msgFile\n");

            # Re-open the source directory into a separate directory listing
            # which we'll search for signature files
            opendir(SIGDIR, $dir)
                or die("ERROR: unable to open $dir, aborting: $!");

            # Get list of all corresponding HSS signature files for the current key
            @sigFiles = grep (/^$msgFile\_\d+\.sig$/, readdir(SIGDIR));

            # Iterate through the list of all signature files and perform the
            # necessary signature verification test
            foreach $sigFile (@sigFiles) {
                # Process the signature verification and track the result
                $numTests++;
                $command = "./$hssVerify $dir/$msgFile $dir/$pubFile $dir/$sigFile";
                $ret = `$command`;

                if ($ret =~ m/Signature verified/) {
                    $passCnt++;
                    print("  $sigFile - PASSED\n");
                }
                else {
                    $failCnt++;
                    print("  $sigFile - FAILED\n");
                }
            }
        }
    }
}
else {
    print("ERROR: signature verification primitive $hssVerify not found\n");
}

# Print out a summary of the run
print("\nSummary:\n");
print("   $numTests tests executed\n");
print("   PASSED = $passCnt\n");
print("   FAILED = $failCnt\n");
