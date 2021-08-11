add_library(ConstantSize MODULE
        # List your source files here.
        ConstantSize.cpp)

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(ConstantSize PRIVATE cxx_range_for cxx_auto_type)

# LLVM is (typically) built with no C++ RTTI. We need to match that.
set_target_properties(ConstantSize PROPERTIES
        COMPILE_FLAGS "-fno-rtti"
        )
# Get proper shared-include behavior (where symbols are not necessarily
# resolved when the shared include is linked) on OS X.
if(APPLE)
  set_target_properties(ConstantSize PROPERTIES
          LINK_FLAGS "-undefined dynamic_lookup"
          )
endif(APPLE)
