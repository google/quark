cmake_minimum_required(VERSION 3.10)
project(quark_src)

set(COMMON_SRC_ROOT
        ${SRC_ROOT}/common
        )
set(COMMON_SRC_ROOT
        ${COMMON_SRC_ROOT}
        PARENT_SCOPE
        )

set(HSS_SRC_ROOT
        ${SRC_ROOT}/hss
        )
set(HSS_SRC_ROOT
        ${HSS_SRC_ROOT}
        PARENT_SCOPE
        )

set(XMSSMT_SRC_ROOT
        ${SRC_ROOT}/xmssmt
        )
set(XMSSMT_SRC_ROOT
        ${XMSSMT_SRC_ROOT}
        PARENT_SCOPE
        )

add_subdirectory(${COMMON_SRC_ROOT})
set(COMMON_SRC_FILES
        ${COMMON_SRC_FILES}
        PARENT_SCOPE
        )

add_subdirectory(${HSS_SRC_ROOT})
add_subdirectory(${XMSSMT_SRC_ROOT})
