cmake_minimum_required (VERSION 3.0)
project (sgx_interface_side_channel)
# 版本号
set (Tutorial_VERSION_MAJOR 1)
add_subdirectory(LLVMPasses)
add_subdirectory(sgxtaintanalysis)

add_executable(Tutorial tutorial.cxx)