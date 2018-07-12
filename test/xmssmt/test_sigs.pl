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
#   This script scans <$dir> to find a list of all  public key files
#   (<@files>) and then uses these to search for corresponding signature
#   files (<@sigFiles>).  It then attempts to verify the generated signatures
#   and tracks the resulting pass/fail stats that it prints onscreen at
#   completion.
#
#   Public key files are identified by their file name formats which are
#   expected to be of the form(s):
#
#        xmssmt_sha2_<h>_<L>_256.key.pub
#        xmss_sha2_<h>.key.pub
#
#   where <h> corresponds to the total tree height (i.e., in XMSS-MT it is
#   the sum of the individual sub-trees, and in XMSS it is the height of the
#   single tree), and <L> corresponds to the number of sub-tree levels.
#
#   As per the XMSS specification, all trees use a Winternitz OTS with
#   w = 4, and all sub-trees are the same size (i.e., in XMSS-MT the values
#   {h, L} = {60, 6} implies 6 sub-trees of height 10).
#
#   The corresponding signature files are identified by their file name formats
#   which are expected to be of the form(s):
#
#        xmssmt_sha2_<h>_<L>_256_<#>.sig
#        xmss_sha2_<h>_<#>.sig
#
#   where <#> is an integer value ranging from 0 onwards used to uniquify
#   the signature files when multiple signatures are generated for a given
#   XMSS/XMSS-MT value.
#
#   The signed file is identified by its file name format which is expected
#   to be of the form(s):
#
#        xmssmt_sha2_<h>_<L>_256
#        xmss_sha2_<h>_256
#
#   The verification primitive is specified via <$xmssVerify>.
#
#================================================================================
use strict;
use warnings;

#================================================================================
# Variables
#================================================================================
my $xmssVerify = "demo";   # Verification primitive used for XMSS/XMSS-MT signatures
my $command;               # Will contain the command line we execute
my $ret;                   # Will capture stdout of command line executed
my $numTests = 0;          # Total number of signature verifications that we've performed
my $passCnt = 0;           # Number of signature verification checks that have passed
my $failCnt = 0;           # Number of signature verification checks that have failed
my @files;                 # Array containing list of public key files
my $file;                  # Stem of filename used to identify other file types
my $keyFile;               # Public key filename
my @sigFiles;              # Array containing list of signature files
my $sigFile;               # Iterator that we use to walk through @sigFiles

# Directory where we'll be looking for signatures, public keys, signed files
my $dir = "./Vectors";

#================================================================================
# Program
#================================================================================
# No sense doing anything if no verification primitive is present
if (-e $xmssVerify) {

    # Attempt to open the source directory where we'll find the files we need to
    # perform the signature verifications
    opendir(DIR, $dir)
        or die("ERROR: unable to open $dir, aborting: $!");

    # Looking for file groups of the form:
    #
    # XMSS:
    #   signature files: xmss_sha2_<hTotal>_256_<#>.sig  *** THIS IS WHAT WE LOOK FOR ***
    #       input files: xmss_sha2_<hTotal>_256
    #  public key files: xmss_sha2_<hTotal>_256.key.pub
    #
    # XMSS-MT:
    #   signature files: xmssmt_sha2_<hTotal>_<d>_256_<#>.sig *** THIS IS WAHT WE LOOK FOR ***
    #       input files: xmssmt_sha2_<hTotal>_<d>_256
    #  public key files: xmssmt_sha2_<hTotal>_<d>_256.key.pub
    #

    # Get list of all public key files in the given directory
    @files = grep ( /^xmss.*_256\.key\.pub$/, readdir(DIR) );

    # Iterate through the list of public key files to see which we can use to
    # perform signature verification tests
    foreach $file (@files) {
        $keyFile = $file;

        # Get the stem filename and check that the corresponding signed file
        # and public key exists before attempt to do any signature verification
        # tests
        $file =~ m/(.*_256)\.key\.pub$/;
        $file = $1;
        if ((-e "$dir/$file") &&
            (-e "$dir/$keyFile")) {
            print("Validating signatures for $file\n");

            # Re-open the source directory into a separate directory listing which
            # we'll search for signature files
            opendir(SIGDIR, $dir)
                or die("ERROR: unable to open $dir, aborting: $!");

            # Get list of all corresponding XMSS/XMSS-MT signature files for the current key
            @sigFiles = grep ( /^$file\_\d+\.sig$/, readdir(SIGDIR) );

            # Iterate through the list of all signature files to see which we can
            # use to perform signature verification tests
            foreach $sigFile (@sigFiles) {
                $numTests++;
                $command = "./$xmssVerify $dir/$file $dir/$keyFile $dir/$sigFile";
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
    print("ERROR: signature verification primitive $xmssVerify not found\n");
}

# Print out a summary of the run
print("\nSummary:\n");
print("   $numTests tests executed\n");
print("   PASSED = $passCnt\n");
print("   FAILED = $failCnt\n");
