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
#   (<@files>) and then uses that to search for corresponding signature files
#   (generated using the gensigs.pl script) (<@sigFiles>).  It then attempts
#   to verify the generated signatures and tracks the resulting pass/fail
#   stats that it prints onscreen at completion.
#
#   Public key files are identified by their file name formats which are
#   expected to be of the form:
#
#        hss_<h0>.<w0>[_<hi>.<wi>]*.pub
#
#   where there can be 0 to 7 _<hi>.<wi> terms depending on
#   the L value (0 for L = 1, 7 for L = 8).
#
#   The corresponding signature files are identified by their file name formats
#   which are expected to be of the form:
#
#        hss_<h0>.<w0>[_<hi>.<wi>]*_<#>.sig
#
#   where <#> is an integer value ranging from 0 onwards (dictated by the
#   <$numSigs> parameter in gensigs.pl).
#
#   The signed file is identified by its file name format which is expected
#   to be f the form:
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
my @files;              # Array containing list of public key files
my $file;               # Iterator that we use to walk through @files
my @sigFiles;           # Array containing list of signature files
my $sigFile;            # Iterator that we use to walk through @sigFiles

# Directory where we'll be looking for signatures, public keys, signed files
my $dir = "../hash-sigs-quark/Foobar";

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
    @files = grep (/^hss_.*\.pub$/, readdir(DIR) );

    # Iterate through the list of public key files to see which we can use to
    # perform signature verification tests
    foreach $file (@files) {
        # Get the stem filename and check that the corresponding signed file
        # exists before attempting to do any signature verification tests
        $file =~ m/(.*)\.pub$/;
        $file = $1;
        if (-e "$dir/$file") {
            print("Validating signatures for $file\n");

            # Re-open the source directory into a separate directory listing which
            # we'll search for signature files
            opendir(SIGDIR, $dir)
                or die("ERROR: unable to open $dir, aborting: $!");

            # Get list of all corresponding HSS signature files for the current key
            @sigFiles = grep (/^$file\_\d+\.sig$/, readdir(SIGDIR));

            # Iterate through the list of all signature files to see which we can
            # use to perform signature verification tests
            foreach $sigFile (@sigFiles) {
                # Get the stem filename and use it to create temporary signature
                # file since we require the signature file and the signed file to
                # be the same up to the ".sig" suffix and its simpler to do this
                # than to re-write the demo.c application (I use that term loosely
                # as demo.c is a total hack job)
                $sigFile =~ m/(.*)_\d+\.sig$/;
                $ret = `cp $dir/$sigFile $dir/$1.sig`;
                $sigFile = $1;

                # Process the signature verification and track the result
                $numTests++;
                $command = "./$hssVerify $dir/$file $dir/$sigFile";
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

            # Get rid of the temprorary signature file (if we created it in
            # the first place!)
            if (-e "$dir/$1.sig") {
                $ret = `rm $dir/$1.sig`;
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
