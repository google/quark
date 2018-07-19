#[[
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]
cmake_minimum_required(VERSION 3.0)
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
        ${COMMON_TEST_FILES}
        )
set_target_properties(xmssmt_kat
        PROPERTIES OUTPUT_NAME
        "kat"
        )

add_executable(xmssmt_demo
        demo.c
        ${COMMON_SRC_FILES}
        ${COMMON_TEST_FILES}
        )
set_target_properties(xmssmt_demo
        PROPERTIES OUTPUT_NAME
        "demo"
        )
