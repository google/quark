cmake_minimum_required(VERSION 3.10)
project(hss_verify_test)
message("common src root ${COMMON_SRC_ROOT}")

include_directories(${HSS_SRC_ROOT} ${COMMON_SRC_ROOT})

link_directories(${HSS_SRC_ROOT} ${COMMON_SRC_ROOT})
link_libraries(hssVerify)
link_libraries(quarkCommon)

add_executable(hss_kat kat.c)
set_target_properties(hss_kat PROPERTIES OUTPUT_NAME "kat")

add_executable(hss_verify_test test.c)
set_target_properties(hss_verify_test PROPERTIES OUTPUT_NAME "test")

add_executable(hss_demo demo.c)
set_target_properties(hss_demo PROPERTIES OUTPUT_NAME "demo")