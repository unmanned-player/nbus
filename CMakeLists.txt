# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()

if (CMAKE_VERSION VERSION_LESS 3.0)
    project(nbus)
    set(PROJECT_VERSION_MAJOR "0")
    set(PROJECT_VERSION_MINOR "1")
    set(PROJECT_VERSION_PATCH "0")
    set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
else()
    project(nbus LANGUAGES C VERSION 0.1.0)
endif()

include(CheckIncludeFile)
include(CheckTypeSize)
include(CTest)
include(GNUInstallDirs)

find_package(PkgConfig)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)

# Sorry, Windows not allowed. Maybe for a long time.
if (NOT UNIX)
    message(FATAL_ERROR "Target platform must be UNIX for nBus to work.")
endif()

option(BUILD_AGENT          "Build network forwarding agent"    OFF) # Coming Soon...
option(BUILD_CLI            "Also build CLI tool"               OFF)
option(BUILD_DOCS           "Build doxygen based API documents" OFF)
option(BUILD_EXAMPLES       "Build some examples to play with"  OFF)
option(BUILD_TESTS          "Build some speed-tests"            OFF)
option(ENABLE_LUA           "Enable Lua bindings"               OFF)

if (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    set(CMAKE_C_FLAGS_DEBUG             "-D_DEBUG -O0 -g -fstandalone-debug")
    set(CMAKE_C_FLAGS_RELEASE           "-DNDEBUG -Ofast")
    set(CMAKE_C_FLAGS_MINSIZEREL        "-DNDEBUG -Oz")
elseif (${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
    set(CMAKE_C_FLAGS_DEBUG             "-D_DEBUG -O0 -ggdb -g3")
    set(CMAKE_C_FLAGS_RELEASE           "-DNDEBUG -O3")
    set(CMAKE_C_FLAGS_MINSIZEREL        "-DNDEBUG -Os")
endif()


if (${CMAKE_C_COMPILER_ID} STREQUAL "GNU" OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -pedantic-errors")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Werror")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wall")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wextra")
endif()

if (${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Waggregate-return")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wbad-function-cast")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wcast-align")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wcast-qual")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wdeclaration-after-statement")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wfloat-equal")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wformat=2")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wlogical-op")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wmissing-declarations")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wmissing-include-dirs")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wmissing-prototypes")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wnested-externs")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wpointer-arith")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wredundant-decls")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wsequence-point")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wshadow")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wstack-protector")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wstrict-prototypes")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wswitch")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wswitch-bool")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wswitch-default")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wswitch-enum")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wundef")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wunreachable-code")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wunused-but-set-parameter")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wwrite-strings")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wformat-nonliteral")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wformat-security")

    set(CMAKE_EXE_LINKER_FLAGS          "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-undefined -Wl,--gc-sections")
elseif(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wmost")
    set(BUS_C_FLAGS                     "${BUS_C_FLAGS} -Wno-padded")
endif()

add_definitions(-D__STDC_LIMIT_MACROS)
add_definitions(-D_XOPEN_SOURCE=700)

add_definitions(-DPROG_VERSION="${PROJECT_VERSION}")

# Process some options and build compile time states.
if (NOT NBUS_CTX_NAME_PREFIX)
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(NBUS_CTX_NAME_PREFIX "nbus:")
    else()
        set(NBUS_CTX_NAME_PREFIX "/var/run/nbus/")
    endif()
endif()

# According to POSIX, UNIX_PATH_MAX is removed and the sizeof (struct sockaddr_un.sun_path) is intentionally left
# undefined. So we need to get the size of it in a portable way.
set(CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h" "sys/un.h")
check_type_size("((struct sockaddr_un*)0)->sun_path" __sizeof_sun_path)
string(LENGTH ${NBUS_CTX_NAME_PREFIX} __ctx_pfx_len)
# Calculate -- Maximum space in path variable, minus name prefix length, minus 2 null ('\0') terminators at [0] and
# [last].
math(EXPR __nbus_ctx_name_len "${__sizeof_sun_path} - ${__ctx_pfx_len} - 2")

if (NBUS_CTX_NAME_PREFIX MATCHES "^(/)")
    set(NBUS_PREFIX_IS_PATH     1)
else()
    # Only Linux allows abstract Domain socket names.
    if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "Abstract domain sockets are not available on ${CMAKE_SYSTEM_NAME}.")
    endif()
endif()

find_package(json-c QUIET)
if (json-c_FOUND)
    add_definitions(-DNB__HAS_JSON)
    set(NB_HAS_JSON TRUE)
else()
    set(NB_HAS_JSON FALSE)
endif()

if (PKG_CONFIG_FOUND)
    pkg_check_modules(TINYCBOR tinycbor>=0.5)
    add_definitions(-DNB__HAS_CBOR)
    set(NB_HAS_CBOR TRUE)
else()
    set(NB_HAS_CBOR FALSE)
endif()

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/lib)

add_subdirectory(lib)

if (BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
if (BUILD_TESTS)
    add_subdirectory(tests)
endif()

if (BUILD_CLI)
    add_subdirectory(tools)
endif()
