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
project(quark)

set(COPYRIGHT "Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the \"License\");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an \"AS IS\" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
")

message("${COPYRIGHT}")

set(QUARK_ROOT ${PROJECT_SOURCE_DIR})
message("Quark Project source root: ${QUARK_ROOT}")

set (SRC_ROOT ${QUARK_ROOT}/src)
set (TEST_ROOT ${QUARK_ROOT}/test)

set(CMAKE_C_FLAGS "-g -Wall -Wextra -Werror")
add_subdirectory(${SRC_ROOT})
add_subdirectory(${TEST_ROOT})