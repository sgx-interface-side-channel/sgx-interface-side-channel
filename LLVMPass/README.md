# SGX_Interface_Side_Channel
==========================

The code to mitigate the interface-based side channel now can only be used for development environment, and part of the code is still under active development.

Environment & Prerequisites
---------------------------
- Intel SGX-enabled CPU
- Intel SGX SDK & Driver
- cmake


Build
--------------------------
- Build LLVM backend
~~~~~{.sh}
$ git clone https://github.com/llvm/llvm-project.git
$ mkdir build
$ cd build
$ cmake -G Xcode -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" ../llvm
~~~~~

- Build front-end pass
~~~~~{.sh}
$ LLVM_DIR=/path/to/llvmBuild/share/llvm/cmake cmake ..
  (e.g., $ LLVM_DIR=../../build-llvm/share/llvm/cmake cmake ..)
$ make
~~~~~

Usage
-------------------------
~~~~~{.sh}
$ cd test
$ make
$ ./App
~~~~~

Note
------------------------
