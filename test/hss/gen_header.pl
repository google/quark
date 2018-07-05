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
#================================================================================
# gen_header.pl - generates C header file from {sig, key, msg} file set
#
#   Syntax:
#
#     gen_header.pl -s <sigFile> -m <msgFile> -k <keyFile> -o <outFile>
#
#     where:
#        <sigFile> = name of file containing binary-formatted signature
#        <msgFile> = name of file containing message that was signed
#        <keyFile> = name of file containing binary-formatted public key
#        <outFile> = name of file where C-format array definitions are written
#
#   This script reads in the given {sig, key, msg} file set and then writes
#   their contents into a C-formatted header file that can be compiled into
#   sample applications to perform a Known-Answer-Test (KAT).
#
#================================================================================
use strict;
use warnings;
use Getopt::Long;

#================================================================================
# Variables
#================================================================================
my $sigFile;      # Name of file that contains the binary signature
my $msgFile;      # Name of file that contains the message to be signed
my $keyFile;      # Name of file that contains the public key
my $outFile;      # Name of file that will contain values defined as arrays
my $sigLen = 0;   # Length (in bytes) of signature file
my $msgLen = 0;   # Length (in bytes) of message file
my $keyLen = 0;   # Length (in bytes) of public key file
my $prefix;       # Empty string used to pad the output file
my $byte;         # Byte read from current input file
my $lineLen = 16; # Number of bytes to print per output line
my $sigHandle;    # File handle pointing to signature file
my $msgHandle;    # File handle pointing to message file
my $keyHandle;    # File handle pointing to public key file
my $outHandle;    # File handle pointing to output file

#================================================================================
# Program
#================================================================================

# Attempt to parse the command line to get the necessary arguments
GetOptions(
    "sig|s=s" => \$sigFile,
    "msg|m=s" => \$msgFile,
    "key|k=s" => \$keyFile,
    "out|o=s" => \$outFile)
    or die("USAGE: $0 --sig <fname> --msg <fname> --key <fname> --out <fname>");

# Ensure we have what we need to run the script
if (!defined($sigFile) ||
    !defined($msgFile) ||
    !defined($keyFile) ||
    !defined($outFile)) {
    print("USAGE: $0 --sig <fname> --msg <fname> --key <fname> --out <fname>\n");
    exit 0;
}

# Attempt to open the various files for reading/writing (assume all input
# files are binary format, whereas we'll be writing to a text-based C
# header outt file
open($sigHandle, "<", $sigFile)
    or die("ERROR: unable to open $sigFile, aborting: $!");
binmode($sigHandle);

open($msgHandle, "<", $msgFile)
    or die("ERROR: unable to open $msgFile, aborting: $!");
binmode($msgHandle);

open($keyHandle, "<", $keyFile)
    or die("ERROR: unable to open $keyFile, aborting: $!");
binmode($keyHandle);

open($outHandle, ">", $outFile)
    or die("ERROR: unable to open $outFile, aborting: $!");

# Start processing the file containing the message that was signed
print($outHandle "uint8_t hss_msg[] = { ");
$prefix = "                      ";
while (read($msgHandle, $byte, 1)) {
    if ($msgLen && (($msgLen % 16) == 0)) {
        print($outHandle "\n$prefix");
    }
    $msgLen++;
    printf($outHandle "0x%02x, ", ord($byte));
}
print($outHandle " };\n");
print($outHandle "size_t msgLen = $msgLen;\n\n");
close($msgHandle);

# Start processing the file containing the public key
print($outHandle "const uint8_t hss_pubKey[] = { ");
$prefix = "                               ";
while (read($keyHandle, $byte, 1)) {
    if ($keyLen && (($keyLen % 16) == 0)) {
        print($outHandle "\n$prefix");
    }
    $keyLen++;
    printf($outHandle "0x%02x, ", ord($byte));
}
print($outHandle " };\n");
print($outHandle "size_t keyLen = $keyLen;\n\n");
close($keyHandle);

# Start processing the file containing the signature
print($outHandle "const uint8_t hss_sig[] = { ");
$prefix = "                          ";
while (read($sigHandle, $byte, 1)) {
    if ($sigLen && (($sigLen % 16) == 0)) {
        print($outHandle "\n$prefix");
    }
    $sigLen++;
    printf($outHandle "0x%02x, ", ord($byte));
}
print($outHandle " };\n");
print($outHandle "size_t sigLen = $sigLen;\n");
close($sigHandle);

# Close the output file now that we're done with it
close($outHandle);
