cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 ${BUS_C_FLAGS}")

# When debugging, statically link it.
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -no-pie -static -static-libgcc")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(nbuscli
    nbuscli.c
)
target_link_libraries(nbuscli ${PROJECT_NAME})
if (NB_HAS_JSON)
    target_link_libraries(nbuscli json-c)
endif()
if (NB_HAS_CBOR)
    target_link_libraries(nbuscli tinycbor)
endif()

install(
    TARGETS     nbuscli
    RUNTIME
    DESTINATION usr/bin
)
