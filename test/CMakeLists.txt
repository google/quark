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
project(quark_test)

set(COMMON_TEST_ROOT ${TEST_ROOT}/common)
set(HSS_TEST_ROOT ${TEST_ROOT}/hss)
set(XMSSMT_TEST_ROOT ${TEST_ROOT}/xmssmt)

include_directories(${COMMON_SRC_ROOT})
add_subdirectory(${COMMON_TEST_ROOT})
add_subdirectory(${HSS_TEST_ROOT})
add_subdirectory(${XMSSMT_TEST_ROOT})

