cmake_minimum_required(VERSION 3.10)
project(quark_test)

set(HSS_TEST_ROOT ${TEST_ROOT}/hss)
set(XMSSMT_TEST_ROOT ${TEST_ROOT}/xmssmt)

include_directories(${COMMON_SRC_ROOT})
add_subdirectory(${HSS_TEST_ROOT})
add_subdirectory(${XMSSMT_TEST_ROOT})

