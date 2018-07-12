/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef QUARK_RET_CODE_STRINGS_H
#define QUARK_RET_CODE_STRINGS_H

#ifdef __cplusplus
extern "C" {
#endif

char* g_retcode_strings[SIG_NUM_RETCODES] = {
    "SIG_OK",
    "SIG_INVALID_SIG",
    "SIG_INVALID_PARAM",
    "SIG_INVALID_LMS_KEY_LEN",
    "SIG_INVALID_LMS_SIG_LEN",
    "SIG_INVALID_LMS_TYPE",
    "SIG_INVALID_LMS_NODE",
    "SIG_INVALID_OTS_KEY_LEN",
    "SIG_INVALID_OTS_SIG_LEN",
    "SIG_INVALID_OTS_TYPE",
    "SIG_INVALID_HSS_KEY_LEN",
    "SIG_INVALID_HSS_SIG_LEN",
    "SIG_INVALID_HSS_LEVELS",
    "SIG_FLASH_READ_ERROR",
    "SIG_INSUFFICIENT_MEMORY"
};

#ifdef __cplusplus
}
#endif
#endif //QUARK_RET_CODE_STRINGS_H

