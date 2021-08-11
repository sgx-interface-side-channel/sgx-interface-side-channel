# SGX_Interface_Side_Channel
==========================

## Introduction

This repository is used for mitigate SGX Interface-based side-channel attack found by [ ]. We use LLVM pass to transform the IR(Intermediate representation) of the source code you want to use. And we use Phasar[] to do taint analysis in order to find all the branches and loops in the program, so that we can make constant control flow.

Environment & Prerequisites
---------------------------

- Intel SGX-enabled CPU
- Intel SGX SDK & Driver
- CMake
- LLVM 9.0.0 (build from source, linking problem may occur if you are using LLVM from apt.llvm.org)


Build
--------------------------
```bash
git clone git@gitlab.com:shellb34r/sgx_interface_side_channel.git
mkdir build
cd build
CMAKE -DCMAKE_BUILD_TYPE=RELEASE -DCMAKE_C_COMPILER=/path/to/your/clang -DCMAKE_CXX_COMPILER=/path/to/your/clang++ ..
make -j $(nproc) # or use a different number of cores to compile it
sudo make install # if you wish to install Phasar system wide
```

Usage
-------------------------
~~~~~{.sh}

~~~~~

Note
------------------------

Please look at phasar's official website for help if you meet some problems during the build of Phasar, 

## References



