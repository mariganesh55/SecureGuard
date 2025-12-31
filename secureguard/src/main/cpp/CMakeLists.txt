cmake_minimum_required(VERSION 3.22.1)

project("secureguard-native")

# Add C++ source files
add_library(
        secureguard-native
        SHARED
        security_checks.cpp
        native_bridge.cpp
)

# Include directories
target_include_directories(secureguard-native PRIVATE ${CMAKE_SOURCE_DIR})

# Link libraries
find_library(log-lib log)
find_library(dl-lib dl)
target_link_libraries(secureguard-native ${log-lib} ${dl-lib})

# EXPERT-PROOF: Compiler flags for maximum security
# -O3: Maximum optimization (makes reverse engineering harder)
# -fvisibility=hidden: Hide all symbols by default
# -ffunction-sections -fdata-sections: Separate functions/data for better optimization
# -fstack-protector-all: Stack protection
# -D_FORTIFY_SOURCE=2: Additional runtime checks
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3 -fvisibility=hidden -ffunction-sections -fdata-sections -fstack-protector-all -D_FORTIFY_SOURCE=2")

# EXPERT-PROOF: Linker flags for symbol stripping and security
# -Wl,--gc-sections: Remove unused sections
# -Wl,--strip-all: Strip all symbols
# -Wl,-z,relro: Read-only relocations
# -Wl,-z,now: Immediate binding (prevents GOT hijacking)
# -Wl,--exclude-libs,ALL: Hide all static library symbols
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all -Wl,-z,relro -Wl,-z,now -Wl,--exclude-libs,ALL")

# EXPERT-PROOF: Release-only optimizations
if(CMAKE_BUILD_TYPE MATCHES Release)
    # LTO for even better obfuscation
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -flto")
endif()
