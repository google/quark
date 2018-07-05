cmake_minimum_required(VERSION 3.10)
project(xmssmt_verify)

include_directories(${COMMON_SRC_ROOT} ${XMSSMT_SRC_ROOT})
add_library(xmssmtVerify ${XMSSMT_SRC_ROOT}/verify.c )
