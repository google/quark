# Post-Quantum Verified Boot

This repository contains hash-based signature verification code that is
optimized for low-end ARM-based IoT devices. 

Currently supported schemes include HSS and XMSS-MT.

The verification code is contained in the ```src``` module and various 
test programs are in the ```test``` module.

## Building
Simple recursive Makefiles are provided arr the root and module levels.  
The outputs of these Makefiles are libraries in the ```src/hss``` and 
```src/xmssmt``` directories which implement the verification code as well as 
test executables in the ```test``` module.

CMake projects are also provided.

