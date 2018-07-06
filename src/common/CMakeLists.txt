cmake_minimum_required(VERSION 3.10)
project(quark_common)

set(COMMON_SRC_FILES
        ${COMMON_SRC_ROOT}/endian_utils.c
        ${COMMON_SRC_ROOT}/endian_utils.h
        ${COMMON_SRC_ROOT}/hash_wrappers.c
        ${COMMON_SRC_ROOT}/hash_wrappers.h
        ${COMMON_SRC_ROOT}/sha256.c
        ${COMMON_SRC_ROOT}/sha256.h
        )

set(COMMON_SRC_FILES
        ${COMMON_SRC_FILES}
        PARENT_SCOPE
        )