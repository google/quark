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
