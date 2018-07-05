cmake_minimum_required(VERSION 3.10)
project(xmssmt_verify_test)

include_directories(${COMMON_SRC_ROOT} ${XMSSMT_SRC_ROOT})

link_directories(${COMMON_SRC_ROOT} ${XMSSMT_SRC_ROOT})
link_libraries(xmssmtVerify)
link_libraries(quarkCommon)

add_executable(xmssmt_kat kat.c)
set_target_properties(xmssmt_kat PROPERTIES OUTPUT_NAME "kat")

add_executable(xmssmt_verify_test test.c)
set_target_properties(xmssmt_verify_test PROPERTIES OUTPUT_NAME "test")
