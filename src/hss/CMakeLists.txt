cmake_minimum_required(VERSION 3.10)
project(hss_verify)

include_directories(${COMMON_SRC_ROOT}
        ${HSS_SRC_ROOT}
        )

add_library(hssVerify
        ${HSS_SRC_ROOT}/verify.c
        ${COMMON_SRC_FILES}
        )
