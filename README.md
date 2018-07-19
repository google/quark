# Project Quark
__Post-Quantum Verified Boot for IoT Devices__

This repository contains work-in-progress hash-based signature verification code that is optimized for low-end ARM-based IoT devices. 

IoT devices have unique security requirements that include the following:

1. Unlike desktops, laptops and phones, they may not be associated with an individual that could keep the device up-to-date, and they are not necessarily 'always on', or even 'occasionally on.' 

2. Furthermore, many of these devices are battery powered, with anemic compute resources and constrained bandwidth availability. 

3. These IoT devices are often installed, ignored, and may need to be in operation for several years. 

To keep these devices secure, it is important to support Verified Boot, and to sign Over The Air (OTA) firmware updates. These require signature schemes that provide compact signatures, and support efficient signature verification. 

Furthermore, since these devices may operate 'in the wild' for several years, perhaps decades, the signature scheme needs to be resilient against anticipated attacks. 

One possible attack would be due to sufficiently large quantum computers that could break RSA and ECC-based signature schemes. There is no consensus regarding when these quantum attacks might become practical, but it is estimated to be between 10-15 years from now. 

Hash-based signatures are believed to be resilient against quantum attacks, have been around for a few decades and hence are well-understood from a security perspective. They can be efficient, but their signature sizes tend to be larger than RSA/ECDSA equivalents. 

These hash-based signatures can be either stateful or stateless, and the former tend to provide more compact signatures than the latter. There are two candidate standards for stateful signatures, one of which is an IETF RFC, the other of which is still in the IETF draft stage:

1. XMSS (RFC 8391)
2. HSS

This project hosts just the signature verification portions of these schemes, which have been optimized to run on low-end ARM devices. The initial version of this code was authored by Crypto4A, Inc., one of our Industry partners that is based in Ottawa, Canada. 

A limitation of stateful signatures is that any misuse of state would completely break security. To address this, Google is collaborating with Stanford University, one of our Academic Research partners, to explore techniques to make these stateful signatures more resilient against limited misuse of state.

There are currently no plans to productize, or officially support this code at this time. This will continue to be work-in-progress for the forseeable future. You are encouraged to leverage this code in your own experiments, and we welcome collaboration. 

The initial version of this code was authored under contract from Google by Crypto4A, Inc., one of our Industry partners that is based in Ottawa, Canada.

## Building
Simple recursive Makefiles are provided at the root and module levels.  
The outputs of these Makefiles are libraries in the ```src/hss``` and 
```src/xmssmt``` directories which implement the verification code as well as 
test executables in the ```test``` module.

CMake projects are also provided.

## Copyright
Copyright &copy; 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License



