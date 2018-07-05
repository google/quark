cmake_minimum_required(VERSION 3.10)
project(hss_verify_test)
message("common src root ${COMMON_SRC_ROOT}")

include_directories(${HSS_SRC_ROOT} ${COMMON_SRC_ROOT} ../common)

link_directories(${HSS_SRC_ROOT} ${COMMON_SRC_ROOT})
link_libraries(hssVerify)
link_libraries(quarkCommon)

set(TEST_VECTORS
        hss_ref_20_2.h
        hss_ref_40_8.h
        hss_ref_60_3.h
        hss_ref_60_6.h
        hss_ref_20_4.h
        hss_ref_40_2.h
        hss_ref_40_4.h
        hss_vectors_001.h)

add_executable(hss_kat kat.c)
set_target_properties(hss_kat PROPERTIES OUTPUT_NAME "kat")

add_executable(hss_verify_test test.c ${TEST_VCTORS})
set_target_properties(hss_verify_test PROPERTIES OUTPUT_NAME "test")

add_executable(hss_demo demo.c)
set_target_properties(hss_demo PROPERTIES OUTPUT_NAME "demo")