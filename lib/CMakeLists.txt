# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${BUS_C_FLAGS}")
# Build the header.
configure_file(nbus.h.in ${CMAKE_BINARY_DIR}/nbus/nbus.h)

include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(lib_srcs
    nbus.c
)

# Build library in a way, BUILD_SHARED_LIBS is respected.
add_library(${PROJECT_NAME} ${lib_srcs})

set_target_properties(
    ${PROJECT_NAME}
PROPERTIES
    SOVERSION                 ${PROJECT_VERSION}
    VERSION                   ${PROJECT_VERSION}
    PUBLIC_HEADER             "${CMAKE_BINARY_DIR}/nbus/nbus.h"
    ARCHIVE_OUTPUT_DIRECTORY  ${CMAKE_INSTALL_LIBDIR}
    LIBRARY_OUTPUT_DIRECTORY  ${CMAKE_INSTALL_LIBDIR}
    OUTPUT_NAME               ${PROJECT_NAME}
)

if (BUILD_DOCS)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        file(WRITE ${CMAKE_BINARY_DIR}/doxygen.cfg
        "
            PROJECT_NAME            = ${PROJECT_NAME}
            WARNINGS                = YES
            WARN_NO_PARAMDOC        = YES
            FILE_PATTERNS           = *.h
            QUIET                   = YES
            CLASS_DIAGRAMS          = NO
            HAVE_DOT                = NO
            EXTRACT_STATIC          = YES
            OUTPUT_DIRECTORY        = ${CMAKE_BINARY_DIR}/docs
            FULL_PATH_NAMES         = NO
            STRIP_FROM_PATH         = ${CMAKE_SOURCE_DIR};${CMAKE_BINARY_DIR}
            INPUT                  += ${CMAKE_BINARY_DIR}/nbus/nbus.h
            EXTRACT_ALL             = YES
        "
        )

        add_custom_target(doc
            ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/doxygen.cfg
        )
        install(DIRECTORY ${CMAKE_BINARY_DIR}/docs/html/ DESTINATION share/doc/${PROJECT_NAME})
    endif()
endif()

install(
    TARGETS                     ${PROJECT_NAME}
    LIBRARY DESTINATION         ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION   include/${PROJECT_NAME}
)
