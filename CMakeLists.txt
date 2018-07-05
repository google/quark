cmake_minimum_required(VERSION 3.10)
project(quark)

set(QUARK_ROOT ${PROJECT_SOURCE_DIR})
set (SRC_ROOT ${QUARK_ROOT}/src)
set (TEST_ROOT ${QUARK_ROOT}/test)

set(CMAKE_C_FLAGS "-g -Wall -Wextra")
add_subdirectory(${SRC_ROOT})
add_subdirectory(${TEST_ROOT})