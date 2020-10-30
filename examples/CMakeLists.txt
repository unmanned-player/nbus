# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${BUS_C_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS          "${CMAKE_EXE_LINKER_FLAGS} -no-pie -static -static-libgcc")

function(genexe out sources)
    add_executable("${out}" "${sources}")
    target_link_libraries("${out}" "${PROJECT_NAME}")
    if (NB_HAS_JSON)
        target_link_libraries("${out}" json-c)
    endif()
    if (NB_HAS_CBOR)
        target_link_libraries("${out}" tinycbor)
    endif()
endfunction()

genexe("raw-client"         raw-client.c)
genexe("raw-server"         raw-server.c)
genexe("raw-generator"      raw-generator.c)
genexe("raw-listener"       raw-listener.c)
