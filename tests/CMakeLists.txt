# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

include(CheckIncludeFiles)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BUS_C_FLAGS}")

include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(speedtest OBJECT speedtest.c)

check_include_files("libubus.h" HAVE_UBUS_H)

if (HAVE_UBUS_H)
    add_executable(stubus
        stubus.c
        $<TARGET_OBJECTS:speedtest>
    )
    target_link_libraries(stubus ${PROJECT_NAME})
    target_link_libraries(stubus rt dl pthread)
    target_link_libraries(stubus ubus ubox json-c)
endif()

add_executable(stnbus
    stnbus.c
    $<TARGET_OBJECTS:speedtest>
)
target_link_libraries(stnbus ${PROJECT_NAME})
target_link_libraries(stnbus rt dl pthread)
