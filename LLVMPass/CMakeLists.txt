cmake_minimum_required (VERSION 3.0)
project (LLVMPasses)

set(CMAKE_PROJECT_NAME "LLVMPasses")

# LLVM
find_package(LLVM REQUIRED CONFIG)
find_library(LLVM_LIBRARY NAMES llvm REQUIRED)
# hard-coded here(need to be changed to your llvm path)
# I still don't know how to dynamicly find the llvm include path
#include_directories(/usr/local/llvm-9/include/)
#include_directories(/usr/local/llvm-9/include/llvm-c)
#link_directories(/usr/local/llvm-9/lib /usr/local/llvm-9/include)

add_subdirectory(BranchElimination)
#add_subdirectory(ConstantSize)
#add_subdirectory(LoopTrans)
#add_subdirectory(function-name-pass)
#add_subdirectory(function-wrapper-pass)