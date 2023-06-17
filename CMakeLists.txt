# CMake minimum version
cmake_minimum_required(VERSION 3.0)

# project name and languages
project(crtdbg C)

# set output directory (build/)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

##############################################################################

# libcrtdbg0.a
add_library(crtdbg0 STATIC crtdbg.c)
target_compile_definitions(crtdbg0 PRIVATE -DMZCRT_BUILD=1 -D_DEBUG=1)

# tests
add_subdirectory(tests)

##############################################################################
