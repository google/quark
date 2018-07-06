cmake_minimum_required(VERSION 3.10)
project(xmssmt_verify_test)
include_directories(${COMMON_SRC_ROOT} ${XMSSMT_SRC_ROOT} ../common)

link_directories(${XMSSMT_SRC_ROOT})
link_libraries(xmssmtVerify)

set(TEST_VECTORS
        xmss_ref_001.h
        xmss_ref_10.h
        xmss_ref_16.h
        xmss_ref_20.h
        xmssmt_ref_001.h
        xmssmt_ref_20_2.h
        xmssmt_ref_20_4.h
        xmssmt_ref_40_2.h
        xmssmt_ref_40_4.h
        xmssmt_ref_40_8.h
        xmssmt_ref_60_3.h
        xmssmt_ref_60_6.h
        xmssmt_ref_60_12.h
        )

add_executable(xmssmt_kat
        kat.c
        quark_misc.c
        ${COMMON_SRC_FILES}
        ${TEST_VECTORS}
        )
set_target_properties(xmssmt_kat
        PROPERTIES OUTPUT_NAME
        "kat"
        )

add_executable(xmssmt_verify_test
        test.c
        quark_misc.c
        ${COMMON_SRC_FILES}
        )
set_target_properties(xmssmt_verify_test
        PROPERTIES OUTPUT_NAME
        "test"
        )
