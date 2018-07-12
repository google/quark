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
project(hss_verify_test)

include_directories(${HSS_SRC_ROOT} ${COMMON_SRC_ROOT} ../common)

link_directories(${HSS_SRC_ROOT})
link_libraries(hssVerify)

set(TEST_VECTORS
        hss_ref_20_2.h
        hss_ref_40_8.h
        hss_ref_60_3.h
        hss_ref_60_6.h
        hss_ref_20_4.h
        hss_ref_40_2.h
        hss_ref_40_4.h
        hss_vectors_001.h
        )

add_executable(hss_kat
        kat.c
        ${TEST_VECTORS}
        ${COMMON_SRC_FILES}
        ${COMMON_TEST_FILES}
        )
set_target_properties(hss_kat
        PROPERTIES OUTPUT_NAME
        "kat"
        )

add_executable(hss_verify_test
        test.c
        ${TEST_VECTORS}
        ${COMMON_SRC_FILES}
        ${COMMON_TEST_FILES}
        )
set_target_properties(hss_verify_test
        PROPERTIES OUTPUT_NAME
        "test"
        )

add_executable(hss_demo
        demo.c
        ${COMMON_SRC_FILES}
        )
set_target_properties(hss_demo
        PROPERTIES OUTPUT_NAME
        "demo"
        )