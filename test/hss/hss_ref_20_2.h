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

/*
 *  Description : HSS reference vector for KAT.
 */

#ifndef _QUARK_REF_VEC_20_2_H_
#define _QUARK_REF_VEC_20_2_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>
#include "test_vector.h"

const uint8_t hss_pubKey_20_2[] =
    {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x03,
     0x02, 0x67, 0xc4, 0x4a,
     0x52, 0xa3, 0x15, 0xfe, 0xa4, 0xde, 0x57, 0x66, 0x07, 0xef, 0x66, 0xa9,
     0x6c, 0x7e, 0x20, 0x15,
     0xc4, 0x2e, 0x05, 0x7c, 0xd3, 0x05, 0x68, 0xa6, 0x2d, 0xb6, 0xbc, 0xe9,
     0x77, 0x1f, 0x23, 0x03,
     0x42, 0x25, 0x3d, 0x55, 0xfd, 0x20, 0x11, 0x45, 0x1c, 0x64, 0xda, 0xcf,};

const uint8_t hss_msg_20_2[] =
    {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x66,
     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x0a,};

const uint8_t hss_sig_20_2[] =
    {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
     0xa7, 0xa2, 0x3c, 0xad,
     0x7d, 0xe9, 0x51, 0x83, 0x04, 0xc4, 0x21, 0xf0, 0x67, 0x6b, 0x11, 0x0f,
     0x84, 0x74, 0x09, 0x08,
     0x68, 0x79, 0x27, 0x6b, 0x23, 0xa0, 0x66, 0x2b, 0x0f, 0xf8, 0xc0, 0x4e,
     0xff, 0xc0, 0xa5, 0xa8,
     0xb9, 0x1e, 0xd5, 0xff, 0x3c, 0x00, 0x4b, 0x9b, 0x66, 0x8a, 0x0a, 0x65,
     0xfd, 0xdc, 0x63, 0xd2,
     0x9a, 0xde, 0x50, 0xc9, 0x91, 0x5e, 0x9c, 0xce, 0x9a, 0xca, 0xe9, 0xef,
     0x04, 0x54, 0xac, 0xab,
     0x35, 0x00, 0x8a, 0x23, 0xbe, 0x28, 0x74, 0xc0, 0x52, 0xd9, 0x1d, 0x42,
     0x8c, 0x27, 0x0b, 0x3b,
     0x6e, 0xa9, 0x91, 0x0b, 0x08, 0xbd, 0x12, 0x68, 0x35, 0x4d, 0x28, 0xe8,
     0x45, 0x9e, 0x06, 0xbf,
     0x41, 0x03, 0x17, 0xb1, 0xc5, 0x08, 0x68, 0x64, 0xc2, 0x30, 0x23, 0x49,
     0x0d, 0x2f, 0xce, 0x61,
     0xa4, 0xc9, 0xb7, 0xfb, 0xc1, 0xf6, 0x11, 0x3c, 0x53, 0xdd, 0xc8, 0xe8,
     0x93, 0x26, 0x2a, 0xbe,
     0x3d, 0x99, 0x5c, 0x10, 0x72, 0xa5, 0xd7, 0xc3, 0xeb, 0xee, 0xbe, 0x8c,
     0x45, 0x65, 0xfd, 0xb7,
     0x77, 0x83, 0x38, 0x7c, 0xb0, 0x4a, 0xbf, 0x98, 0x77, 0xff, 0x9e, 0x18,
     0x97, 0xf9, 0xf5, 0xbe,
     0x83, 0x6d, 0x6e, 0x36, 0xce, 0x1d, 0x13, 0xd2, 0x33, 0xf1, 0xe8, 0x28,
     0xab, 0x88, 0xc6, 0x8a,
     0xb5, 0x71, 0xbc, 0x75, 0x85, 0x2d, 0x8c, 0x8c, 0xf2, 0x56, 0xa6, 0xce,
     0x47, 0x09, 0x8a, 0xe6,
     0x95, 0x40, 0x9d, 0xfd, 0x68, 0x64, 0x79, 0xb5, 0x1b, 0x5e, 0xeb, 0x38,
     0xa3, 0x9b, 0x84, 0x3e,
     0xc1, 0x37, 0x62, 0xa7, 0x20, 0xa4, 0x63, 0x83, 0xae, 0xd5, 0xf8, 0xc5,
     0x8f, 0xc2, 0xff, 0x2a,
     0x57, 0xf3, 0xa1, 0xfe, 0x60, 0x51, 0xef, 0x63, 0x76, 0x92, 0xff, 0xb5,
     0x95, 0xfe, 0x9e, 0x5e,
     0xa3, 0x34, 0x36, 0xf4, 0xef, 0x00, 0x4a, 0xd9, 0x69, 0xc1, 0xcc, 0x22,
     0x17, 0xca, 0xbb, 0x61,
     0xfa, 0x2e, 0x8c, 0x99, 0xcb, 0xc6, 0x2b, 0xc2, 0xda, 0x5e, 0x05, 0x42,
     0x76, 0xfd, 0x52, 0xf2,
     0x0e, 0x0e, 0x0b, 0x6f, 0x18, 0x81, 0xf7, 0x0f, 0x4f, 0x8b, 0xac, 0xc6,
     0x5b, 0xc0, 0xac, 0xb8,
     0x23, 0x99, 0x2f, 0xe4, 0x5d, 0x09, 0x95, 0xa4, 0x38, 0xbe, 0xd6, 0x0d,
     0x08, 0x31, 0xd9, 0x8e,
     0x86, 0xd4, 0x1e, 0x09, 0x76, 0xda, 0xe8, 0xcd, 0xc2, 0xd1, 0x4e, 0x34,
     0xd0, 0x2e, 0xd7, 0xbe,
     0xac, 0x4e, 0x18, 0x34, 0x77, 0x64, 0x93, 0x87, 0xb2, 0x01, 0x6a, 0x41,
     0xa3, 0x84, 0x9a, 0xf0,
     0x71, 0xe7, 0xda, 0xd2, 0x25, 0x06, 0xf8, 0x99, 0xde, 0x01, 0x79, 0x17,
     0xd4, 0x5f, 0x0c, 0x15,
     0xb6, 0x9d, 0x77, 0x5e, 0x5f, 0xa0, 0x2c, 0x53, 0x73, 0x8d, 0x2e, 0x01,
     0xaf, 0x27, 0xa6, 0xbe,
     0xe2, 0x0d, 0x41, 0x0f, 0x1a, 0x04, 0xe9, 0xa1, 0x29, 0xf2, 0x23, 0xe9,
     0x9d, 0x0e, 0xbf, 0x68,
     0x00, 0x1f, 0x40, 0x30, 0x1b, 0x42, 0x34, 0x7e, 0x17, 0x6e, 0xfd, 0x6b,
     0x70, 0x7f, 0xf6, 0xe6,
     0xc6, 0x26, 0x6c, 0x02, 0xdd, 0x57, 0x6c, 0x2e, 0x2e, 0x15, 0x29, 0x1f,
     0xf6, 0x6a, 0xab, 0x1a,
     0x93, 0x05, 0xfa, 0xc0, 0x75, 0xd3, 0x2f, 0xc2, 0x81, 0x10, 0x5c, 0x5a,
     0x8e, 0x46, 0xe7, 0xf9,
     0x25, 0xd8, 0x4f, 0x07, 0xed, 0xf6, 0x30, 0xaf, 0x91, 0xbd, 0x86, 0x11,
     0x36, 0x2d, 0x72, 0x7a,
     0x7a, 0x79, 0x95, 0xbd, 0xe9, 0x20, 0x7a, 0xc1, 0x10, 0x9f, 0x70, 0x7f,
     0x2e, 0xfa, 0xb3, 0x80,
     0xa3, 0x97, 0x25, 0xd6, 0x96, 0x7c, 0x45, 0x33, 0x5b, 0xcf, 0xeb, 0x96,
     0x24, 0x44, 0xd5, 0xcc,
     0xf6, 0xfe, 0x0e, 0xda, 0x72, 0x01, 0x09, 0x5e, 0x81, 0xf9, 0xbb, 0x73,
     0x13, 0x1c, 0xbe, 0x75,
     0x5e, 0xe3, 0xdd, 0x06, 0xf6, 0x12, 0x9f, 0x3c, 0xd6, 0x1e, 0x75, 0x78,
     0xed, 0xd9, 0xfa, 0x8d,
     0x15, 0xdf, 0x95, 0xec, 0xac, 0x34, 0x0f, 0xb7, 0xea, 0x32, 0x9f, 0x64,
     0xf3, 0x8f, 0xdd, 0x43,
     0xf2, 0xa7, 0x1f, 0xbc, 0xe9, 0xf0, 0x24, 0x66, 0xce, 0xe8, 0xdc, 0xe0,
     0x43, 0x2d, 0x2b, 0x48,
     0x54, 0x3a, 0x43, 0xcc, 0x94, 0x52, 0x11, 0x5e, 0xe5, 0xc6, 0x67, 0xa7,
     0x32, 0xeb, 0x3c, 0x55,
     0xeb, 0x4d, 0x17, 0x0c, 0x5e, 0x1b, 0x7f, 0xbd, 0xfa, 0x92, 0xeb, 0x69,
     0xa2, 0xfb, 0x3f, 0xed,
     0x73, 0x5d, 0x5c, 0xb0, 0xae, 0x27, 0xf0, 0xb7, 0xd8, 0x17, 0x14, 0x4e,
     0x9f, 0x07, 0xb6, 0xf3,
     0x35, 0x7f, 0x3e, 0x14, 0x3f, 0x30, 0x22, 0xc3, 0x21, 0x36, 0xea, 0x84,
     0x25, 0x00, 0x61, 0xb7,
     0x0c, 0xe5, 0x82, 0x7f, 0x02, 0x73, 0x58, 0x5a, 0x77, 0xdf, 0x0d, 0xd6,
     0x02, 0xdd, 0x70, 0xa9,
     0xc4, 0xb1, 0x35, 0x9f, 0x2a, 0x65, 0xa7, 0xb1, 0x89, 0xd6, 0x4e, 0xba,
     0x3e, 0x1b, 0xc6, 0xb1,
     0xa5, 0xfe, 0xb3, 0x91, 0x9e, 0x6a, 0x0e, 0x0b, 0xa8, 0x0d, 0x02, 0x9a,
     0x9f, 0x27, 0x47, 0x3d,
     0x75, 0xde, 0x39, 0x35, 0x64, 0xcf, 0x7a, 0xcb, 0x48, 0x66, 0x34, 0xc4,
     0x3d, 0xb8, 0xdc, 0xdd,
     0x01, 0xe4, 0x60, 0x75, 0xe9, 0x57, 0x81, 0xae, 0xef, 0x06, 0xcc, 0x34,
     0xd6, 0xfb, 0x79, 0x31,
     0xa3, 0x93, 0x39, 0x56, 0x1e, 0x3c, 0x02, 0x88, 0xf7, 0x51, 0xbf, 0x1e,
     0xc0, 0x1c, 0x5f, 0xf3,
     0xf2, 0x63, 0xcc, 0xea, 0x5d, 0x30, 0x69, 0x34, 0x6f, 0xa8, 0xd6, 0x30,
     0x2c, 0x74, 0xe6, 0x37,
     0x8e, 0x60, 0xf9, 0x82, 0xb3, 0x5b, 0x67, 0xce, 0x74, 0x01, 0x96, 0x06,
     0x34, 0x8f, 0x58, 0xe4,
     0x7f, 0xac, 0x11, 0x1a, 0x38, 0xa3, 0x05, 0x48, 0x57, 0x9e, 0x43, 0x8d,
     0xbf, 0xb4, 0xf2, 0x00,
     0x2b, 0xb8, 0xa8, 0x7a, 0x29, 0x68, 0x15, 0x08, 0x2f, 0x0e, 0x0a, 0xf9,
     0xea, 0xa3, 0x32, 0xbe,
     0x1c, 0xa0, 0x56, 0x2b, 0x71, 0x1c, 0x93, 0x27, 0xf8, 0x05, 0x71, 0x1e,
     0x79, 0xfa, 0x2e, 0x48,
     0x78, 0x5f, 0x62, 0x9d, 0x4f, 0x0b, 0xea, 0xf6, 0x74, 0x8b, 0xcd, 0x4c,
     0xd9, 0xd6, 0xaf, 0x2c,
     0x81, 0xa0, 0xc0, 0xf0, 0x49, 0x90, 0x84, 0xc7, 0x8d, 0x45, 0xbf, 0xa6,
     0xfb, 0x1d, 0x20, 0x19,
     0xd7, 0x19, 0x83, 0xff, 0x85, 0xb1, 0xf5, 0xb5, 0x85, 0x33, 0x67, 0xcb,
     0x05, 0x4a, 0x1b, 0xf3,
     0x5b, 0x1c, 0x43, 0x73, 0x49, 0x82, 0x22, 0x08, 0x05, 0xac, 0x2e, 0x5e,
     0x9d, 0xbe, 0x5d, 0xa7,
     0x60, 0x25, 0x81, 0xef, 0x75, 0xef, 0x3f, 0xc3, 0xa1, 0x27, 0x07, 0x2f,
     0x3e, 0x87, 0x11, 0x1e,
     0x1e, 0xef, 0xc2, 0x62, 0x8b, 0xfb, 0x96, 0xd7, 0x9d, 0xf0, 0xb1, 0xeb,
     0x3b, 0xbc, 0xa7, 0xf4,
     0x3e, 0x03, 0xc2, 0xbb, 0x22, 0xee, 0x40, 0x99, 0x04, 0x4a, 0x76, 0xaa,
     0x5a, 0xe5, 0xdc, 0xab,
     0x98, 0x74, 0x13, 0x55, 0x1b, 0x32, 0x21, 0x03, 0xd5, 0x79, 0x97, 0xc4,
     0x25, 0xb7, 0xe3, 0x9d,
     0x8d, 0x70, 0x4f, 0x42, 0xcd, 0xda, 0xbd, 0x0a, 0x35, 0x06, 0x07, 0x03,
     0xde, 0xa3, 0xd1, 0x4a,
     0x38, 0x40, 0x07, 0x65, 0x34, 0xbd, 0x99, 0x0c, 0x0c, 0xbd, 0x4f, 0x71,
     0x1c, 0x2a, 0xf9, 0xeb,
     0xb3, 0xfa, 0x34, 0x85, 0x4d, 0xfd, 0x86, 0x9a, 0x87, 0xec, 0x07, 0x08,
     0xb5, 0x1e, 0x8b, 0x24,
     0xa0, 0x7b, 0x4d, 0x26, 0x55, 0x0d, 0xff, 0x47, 0x58, 0xec, 0x44, 0xc4,
     0xad, 0x99, 0x75, 0x9c,
     0xde, 0x8f, 0x21, 0x31, 0x9f, 0xd4, 0xbc, 0xe3, 0x6a, 0x87, 0xa3, 0x50,
     0x73, 0x2c, 0x95, 0xbb,
     0x74, 0x57, 0x49, 0x19, 0xc3, 0x5f, 0x11, 0xef, 0x39, 0x83, 0xf4, 0x87,
     0xad, 0x50, 0x51, 0x8b,
     0x4e, 0x1e, 0x38, 0x6c, 0x2b, 0x49, 0x6f, 0x35, 0x1d, 0xe6, 0xf8, 0x05,
     0xc8, 0xe5, 0xc3, 0x4e,
     0x4b, 0xd0, 0x35, 0x3d, 0x67, 0x47, 0xc9, 0xb3, 0x79, 0x41, 0xaa, 0x11,
     0xc1, 0x1e, 0x41, 0xd4,
     0x06, 0xc8, 0xc6, 0xae, 0x9e, 0x3d, 0x42, 0x7a, 0xc4, 0xd7, 0xbb, 0xa6,
     0x1c, 0xdd, 0xb9, 0x81,
     0xba, 0x59, 0xac, 0x64, 0xc4, 0x30, 0x76, 0x79, 0xa1, 0x3a, 0xfe, 0x93,
     0xf3, 0xed, 0x4f, 0x2a,
     0x5c, 0x34, 0x4f, 0x0d, 0x28, 0xad, 0x23, 0x29, 0x39, 0x76, 0x65, 0x04,
     0x55, 0x8e, 0x7d, 0x56,
     0x9c, 0xee, 0x58, 0x53, 0x1d, 0x0f, 0x72, 0x18, 0x3f, 0xdb, 0xb4, 0x8a,
     0x50, 0x9e, 0x07, 0x48,
     0xe6, 0x30, 0x7d, 0x80, 0xd2, 0x70, 0x8c, 0xf7, 0x73, 0x31, 0x1c, 0x2d,
     0x1c, 0x81, 0x7a, 0xce,
     0xd2, 0x1e, 0xeb, 0xb8, 0xc2, 0x1f, 0x87, 0xb2, 0x7c, 0x6f, 0x36, 0x06,
     0x94, 0xc8, 0xd3, 0x1c,
     0x5a, 0x73, 0xc1, 0x49, 0xf3, 0x46, 0x96, 0xcf, 0xe0, 0x5b, 0xc7, 0x0b,
     0x58, 0x35, 0x6b, 0xc3,
     0x5e, 0xab, 0x65, 0xc1, 0x6e, 0x99, 0x66, 0xd7, 0x63, 0x62, 0x57, 0x05,
     0x26, 0xa6, 0x94, 0xde,
     0x0c, 0xb5, 0x77, 0x16, 0xf4, 0x1e, 0xef, 0x3b, 0x6c, 0xca, 0x2e, 0xfa,
     0x77, 0x4d, 0xb6, 0xea,
     0x40, 0x62, 0xc6, 0x7f, 0x45, 0x0f, 0x3a, 0x38, 0xdf, 0xdb, 0x05, 0x34,
     0x99, 0x74, 0x55, 0x3d,
     0xb8, 0x7e, 0xfe, 0x5d, 0x01, 0x7a, 0x08, 0x40, 0xc3, 0x6d, 0xec, 0x0b,
     0xa1, 0xcd, 0x7a, 0x6c,
     0x67, 0x5e, 0x69, 0x94, 0xe5, 0xb1, 0xb9, 0xca, 0x74, 0x4f, 0x05, 0x0b,
     0x6c, 0x77, 0x67, 0x72,
     0x3f, 0x7b, 0xd1, 0x15, 0xa3, 0x90, 0x19, 0xfc, 0x90, 0x64, 0x80, 0xf5,
     0x43, 0xc6, 0x8c, 0xb2,
     0xe9, 0xff, 0xa9, 0x44, 0x9b, 0x0b, 0xb8, 0xa7, 0x22, 0xcb, 0x2c, 0x77,
     0xc6, 0x4f, 0xe9, 0x7b,
     0x6e, 0x1c, 0xe3, 0x21, 0x79, 0x5b, 0xfe, 0x7a, 0xaa, 0x1d, 0x62, 0x8e,
     0x0f, 0xa5, 0xde, 0x42,
     0xaa, 0x2c, 0x48, 0xce, 0x7d, 0xf2, 0x0f, 0x2d, 0x9d, 0x2e, 0x70, 0x30,
     0xa8, 0xa2, 0x5f, 0x18,
     0x92, 0x76, 0xef, 0x01, 0x64, 0x7a, 0xd2, 0xb2, 0x04, 0x0f, 0xc2, 0x31,
     0x1e, 0x2f, 0x59, 0xa2,
     0x6e, 0x02, 0xe2, 0x5d, 0x7d, 0x50, 0xab, 0x56, 0x90, 0x9f, 0xb0, 0x74,
     0xbe, 0xbe, 0x18, 0xc8,
     0x6f, 0xd1, 0x60, 0x6a, 0xc5, 0xc1, 0xab, 0xbc, 0xed, 0x3a, 0x60, 0x0a,
     0xb7, 0xd2, 0xff, 0xea,
     0xad, 0xf0, 0xac, 0x5e, 0xb3, 0xcb, 0x97, 0x76, 0x46, 0xf9, 0x3a, 0xd6,
     0xeb, 0xbd, 0x5f, 0x9a,
     0x1a, 0x83, 0x5a, 0xfe, 0x13, 0xce, 0x76, 0x79, 0x72, 0x9e, 0xda, 0xc2,
     0xb9, 0x3e, 0x5b, 0xe1,
     0x62, 0x98, 0x77, 0xa6, 0x92, 0xb3, 0x31, 0x35, 0x5f, 0xf8, 0xf3, 0x68,
     0x2f, 0x3a, 0x8f, 0x1c,
     0x1c, 0xbb, 0xb9, 0x49, 0x96, 0x1e, 0x4b, 0x19, 0x7d, 0x91, 0xcb, 0x27,
     0x2e, 0xca, 0xa9, 0xe2,
     0xcd, 0xb4, 0xd7, 0x16, 0x27, 0x0f, 0x5f, 0x4a, 0x8f, 0xe6, 0x52, 0xae,
     0xa2, 0x8e, 0x87, 0x9d,
     0x0c, 0x81, 0x5a, 0xa8, 0x75, 0xc2, 0xf2, 0x92, 0x7b, 0x02, 0x3a, 0x54,
     0xde, 0xa4, 0x02, 0xe5,
     0xa4, 0x60, 0x9c, 0xdf, 0x05, 0xfe, 0xcf, 0x3d, 0x29, 0x43, 0x6b, 0xb6,
     0xf7, 0x52, 0xe5, 0x45,
     0x60, 0x75, 0x94, 0xe9, 0x37, 0x48, 0x8e, 0x39, 0x31, 0x15, 0x85, 0xec,
     0xf3, 0xba, 0xbd, 0x27,
     0x8f, 0x33, 0xcf, 0x7f, 0x73, 0x29, 0x79, 0x73, 0xf6, 0x71, 0xc7, 0xbd,
     0xd3, 0x06, 0x87, 0xc7,
     0x00, 0x48, 0x01, 0xa1, 0x23, 0x3d, 0xcb, 0xcf, 0xd5, 0x77, 0x20, 0xed,
     0x93, 0xef, 0xc3, 0x45,
     0xb5, 0x47, 0xaa, 0x6c, 0x8b, 0x43, 0xdd, 0x35, 0xa1, 0x8f, 0x76, 0xd6,
     0xce, 0xb9, 0x3a, 0x2b,
     0xe2, 0x2b, 0x5c, 0xb9, 0xef, 0xef, 0x93, 0xf8, 0x59, 0x06, 0xc3, 0xbf,
     0xb9, 0x8f, 0x08, 0x3c,
     0x4d, 0xc1, 0x86, 0x20, 0x7f, 0x7c, 0x59, 0xc7, 0x9d, 0x43, 0x90, 0x48,
     0xbf, 0x02, 0xe2, 0xb8,
     0x3d, 0x55, 0xc2, 0x40, 0x67, 0xd0, 0x59, 0xe4, 0x00, 0x3c, 0xbe, 0xcd,
     0x19, 0xa4, 0xfc, 0xec,
     0xf2, 0x10, 0xaf, 0x2a, 0xee, 0xa0, 0xe3, 0xdf, 0xfb, 0x1b, 0xf5, 0xb6,
     0xce, 0xe0, 0x0d, 0xfd,
     0xce, 0x52, 0x36, 0x88, 0xdc, 0x66, 0x94, 0x04, 0x66, 0x8f, 0x27, 0xe4,
     0xe7, 0x15, 0x9d, 0xf6,
     0x83, 0x2b, 0x8c, 0xda, 0x9b, 0x50, 0x4b, 0x2c, 0xf6, 0xcc, 0x97, 0xd8,
     0x1e, 0x93, 0x73, 0xb5,
     0xa6, 0xf3, 0x52, 0x68, 0x80, 0x7f, 0xfa, 0xaf, 0xdd, 0xee, 0x94, 0x31,
     0xc8, 0x4c, 0x0a, 0x8e,
     0xbf, 0x7d, 0x46, 0x45, 0x56, 0x6d, 0x8d, 0xa1, 0xc3, 0x1d, 0x38, 0x8f,
     0x19, 0x07, 0x21, 0x48,
     0xeb, 0x83, 0x06, 0x59, 0x66, 0x86, 0x0a, 0x11, 0xec, 0x73, 0xf5, 0x35,
     0x76, 0x35, 0x26, 0x58,
     0x5c, 0xf4, 0xae, 0x66, 0xb5, 0x64, 0x8c, 0x03, 0xd3, 0x03, 0x76, 0x4c,
     0x56, 0x94, 0x6a, 0xaf,
     0xcf, 0x9e, 0x45, 0x7f, 0x4f, 0x0b, 0x07, 0x28, 0xb5, 0xc2, 0xeb, 0x2b,
     0x06, 0x66, 0xf1, 0x61,
     0xa4, 0x09, 0x3b, 0x3d, 0xef, 0xc3, 0xc3, 0x01, 0xb9, 0xf1, 0x14, 0x20,
     0x7f, 0x31, 0xfa, 0x9e,
     0x1e, 0x4e, 0x54, 0x24, 0xfc, 0xa7, 0xc9, 0x1e, 0x1f, 0x13, 0x18, 0x51,
     0xb8, 0x33, 0x98, 0x6c,
     0x51, 0xd5, 0x2f, 0x6a, 0xb5, 0xfe, 0xd4, 0xa7, 0xe2, 0x29, 0xa8, 0x83,
     0x5c, 0xa8, 0x1f, 0x4a,
     0x1d, 0xd8, 0xc4, 0x05, 0xad, 0x16, 0xfd, 0xf4, 0x7c, 0x53, 0x4f, 0x58,
     0xf9, 0x09, 0xbb, 0xc8,
     0xfb, 0x80, 0xc7, 0x70, 0xaf, 0xec, 0x65, 0xde, 0xd4, 0x32, 0x03, 0xfa,
     0x16, 0x49, 0x86, 0x74,
     0x69, 0x6a, 0x77, 0x71, 0xef, 0xb9, 0xec, 0xd9, 0xca, 0xb1, 0xfe, 0xe5,
     0x94, 0xcb, 0x3f, 0x29,
     0x09, 0x91, 0x3e, 0x19, 0x4f, 0xac, 0x87, 0x96, 0xe5, 0xe5, 0x1a, 0xbb,
     0x71, 0xdb, 0x85, 0xc4,
     0x46, 0x24, 0x3d, 0x50, 0xef, 0xe4, 0xa3, 0xf4, 0x49, 0x31, 0x35, 0xef,
     0x35, 0xba, 0x2f, 0x07,
     0xa4, 0x12, 0x62, 0xa2, 0xe0, 0x60, 0x82, 0x6c, 0x1b, 0x4f, 0x31, 0x1c,
     0xf3, 0x8b, 0xfa, 0x18,
     0xa9, 0x4f, 0x6a, 0xc3, 0x61, 0xf9, 0x87, 0x60, 0x18, 0x93, 0xf7, 0xda,
     0x5e, 0x68, 0x82, 0x90,
     0xaa, 0xad, 0xec, 0x08, 0x77, 0x2c, 0x3a, 0x22, 0x3f, 0x05, 0x3a, 0x57,
     0x06, 0x5f, 0x01, 0xff,
     0xf8, 0xfb, 0x7b, 0x7e, 0xbc, 0xf9, 0x56, 0x1d, 0x43, 0x18, 0x31, 0x85,
     0xd3, 0x48, 0x9b, 0x12,
     0x2e, 0xf0, 0xda, 0xa5, 0x07, 0x68, 0x04, 0xb3, 0x84, 0x48, 0xde, 0xc9,
     0x4a, 0x77, 0x7e, 0x2e,
     0xce, 0x2e, 0xe4, 0xcf, 0x55, 0x26, 0x00, 0xe1, 0x81, 0xf4, 0xfc, 0x0e,
     0xce, 0x3e, 0xca, 0x86,
     0x1e, 0x8e, 0x93, 0x02, 0xb4, 0x01, 0x14, 0x68, 0x39, 0xae, 0x5e, 0xf7,
     0x80, 0xa4, 0x8f, 0x9a,
     0xbc, 0x15, 0xe2, 0x87, 0x13, 0x2c, 0x32, 0x22, 0x53, 0x28, 0x99, 0x9c,
     0x90, 0x80, 0x58, 0x70,
     0xd0, 0x7e, 0xa6, 0x17, 0xdc, 0xa5, 0x34, 0x06, 0xe3, 0x7d, 0x45, 0x58,
     0xbf, 0x5f, 0xea, 0xf2,
     0xeb, 0xf2, 0x2a, 0xf8, 0x6e, 0x70, 0x1d, 0xc1, 0x7c, 0xd2, 0xc0, 0x8d,
     0x31, 0xef, 0xc6, 0x8a,
     0x73, 0xf9, 0xc0, 0x4a, 0x19, 0x6d, 0x21, 0xf1, 0x54, 0xcb, 0xd0, 0x7c,
     0x54, 0x72, 0xf5, 0x56,
     0x21, 0x2c, 0xb6, 0x91, 0x3c, 0x48, 0x03, 0xfa, 0xfb, 0xaf, 0xe3, 0xfd,
     0xab, 0x09, 0xf6, 0x63,
     0x0c, 0x0a, 0x48, 0xb0, 0x45, 0x21, 0xf3, 0x13, 0x54, 0x6a, 0x6d, 0xf7,
     0x8e, 0x4a, 0x85, 0xb2,
     0x0a, 0xfa, 0xc9, 0xd0, 0xe1, 0x8d, 0x49, 0x14, 0xf5, 0x54, 0xc3, 0x5d,
     0xcf, 0x88, 0xaa, 0x66,
     0xf3, 0x66, 0x16, 0x77, 0x41, 0x18, 0x7d, 0xe7, 0x09, 0xe1, 0xaf, 0x46,
     0x19, 0x43, 0x0b, 0xd9,
     0x44, 0x03, 0x22, 0xcd, 0x5d, 0xd1, 0xad, 0xa8, 0xec, 0x81, 0x84, 0x31,
     0x99, 0xd7, 0x3f, 0x27,
     0x38, 0xf8, 0xa7, 0xf6, 0x8e, 0xf8, 0xc6, 0xd9, 0xe4, 0xc0, 0x9a, 0xe6,
     0x94, 0xe8, 0x5b, 0xa1,
     0xea, 0x18, 0xdb, 0xb8, 0x48, 0xa0, 0x16, 0x32, 0xa7, 0x47, 0x2f, 0x35,
     0xf6, 0xa3, 0xbc, 0x34,
     0x79, 0x8e, 0x06, 0x42, 0x46, 0x4b, 0x87, 0x7f, 0x59, 0xe4, 0x55, 0x87,
     0x25, 0x14, 0xc4, 0x0f,
     0xed, 0x71, 0xf3, 0x2d, 0x66, 0x6a, 0xf7, 0xb3, 0xed, 0x3c, 0xdf, 0x04,
     0xf8, 0x9f, 0x7b, 0x62,
     0x03, 0x26, 0xb9, 0xfa, 0x30, 0x2d, 0xd8, 0xe1, 0x1b, 0x06, 0x39, 0x57,
     0x39, 0x2a, 0xec, 0xd8,
     0xbd, 0x29, 0xca, 0xd9, 0xde, 0xe9, 0xd3, 0x8d, 0x17, 0x52, 0x36, 0x20,
     0x00, 0x00, 0x00, 0x06,
     0x8f, 0xd1, 0x22, 0x1e, 0x33, 0x98, 0x72, 0x2b, 0xfd, 0x59, 0x0d, 0xfa,
     0xd8, 0xc3, 0x15, 0x24,
     0xac, 0xeb, 0x0a, 0x2d, 0xe5, 0x86, 0xc0, 0x8a, 0x4a, 0x13, 0xbd, 0x0b,
     0x85, 0xb8, 0x3d, 0x35,
     0x15, 0x74, 0xd3, 0x54, 0x2f, 0x9b, 0x5c, 0xa1, 0x8c, 0x94, 0x71, 0x3a,
     0x33, 0x76, 0x25, 0x16,
     0xc5, 0x17, 0xbc, 0x70, 0xff, 0xbb, 0xea, 0x23, 0x76, 0x37, 0x6e, 0x8a,
     0xb8, 0xf8, 0x7a, 0x53,
     0xdb, 0xfc, 0x0f, 0x0b, 0x38, 0xf8, 0x44, 0x6f, 0x60, 0x8e, 0xe1, 0x0a,
     0xad, 0x28, 0x33, 0x57,
     0xb6, 0xae, 0xc7, 0x2a, 0x96, 0xad, 0x3b, 0xc5, 0x40, 0x5d, 0x90, 0x19,
     0xed, 0x41, 0x57, 0x1b,
     0xfc, 0x90, 0x5e, 0xad, 0xfa, 0xc7, 0x89, 0x3a, 0x2a, 0x7f, 0x0b, 0x3f,
     0x1b, 0xad, 0x7d, 0xd0,
     0x84, 0xef, 0xb3, 0x11, 0xe1, 0xc3, 0x7b, 0x84, 0xea, 0x3a, 0xcc, 0x8a,
     0x19, 0x8d, 0x2c, 0x95,
     0x9a, 0x0c, 0x95, 0x4e, 0x19, 0x06, 0x00, 0x82, 0xc1, 0xb7, 0x67, 0x6c,
     0x03, 0xd9, 0xdf, 0x23,
     0x26, 0xf5, 0xc4, 0x78, 0x62, 0x83, 0x6d, 0xd4, 0x36, 0x13, 0x84, 0x6e,
     0xd6, 0xa1, 0xc9, 0x51,
     0xf0, 0x15, 0x9c, 0xdd, 0xac, 0xda, 0xd8, 0x48, 0x4b, 0xf9, 0xec, 0x0a,
     0x54, 0xf4, 0xad, 0xc9,
     0xdf, 0xac, 0xa7, 0x26, 0x6a, 0x4d, 0xb9, 0x84, 0xa7, 0x97, 0x5d, 0xbb,
     0x73, 0xf3, 0x36, 0x49,
     0x62, 0xc3, 0xf3, 0x38, 0x38, 0xfc, 0x90, 0xdd, 0x69, 0xea, 0x93, 0x1e,
     0x5b, 0xe5, 0xff, 0x0b,
     0xcd, 0x1c, 0x88, 0xa0, 0x02, 0xb9, 0x34, 0x8f, 0x18, 0x23, 0xf8, 0x86,
     0xef, 0xf1, 0xec, 0x35,
     0x48, 0xc3, 0x3d, 0x5d, 0x01, 0x70, 0xdb, 0x0d, 0x95, 0x7e, 0xd4, 0xda,
     0xe2, 0x58, 0xcd, 0x42,
     0x11, 0x34, 0xcf, 0x5c, 0xaf, 0xb0, 0x32, 0x45, 0x13, 0x67, 0x21, 0x58,
     0x1f, 0x26, 0xe3, 0xdd,
     0xff, 0x47, 0x60, 0x11, 0x63, 0xb5, 0xdd, 0x00, 0x46, 0x53, 0x2b, 0x7d,
     0x64, 0xa0, 0x96, 0xa1,
     0x0d, 0x98, 0xa0, 0xfd, 0x7a, 0xd8, 0x13, 0x26, 0xd6, 0x9e, 0x6a, 0x58,
     0x97, 0x46, 0x1f, 0x77,
     0x60, 0x5a, 0xae, 0x4b, 0x14, 0x4b, 0x7c, 0x5d, 0xfa, 0x72, 0x56, 0xb9,
     0x35, 0xc6, 0x5b, 0x3e,
     0x60, 0x40, 0x4d, 0x51, 0xbe, 0xdd, 0xb5, 0x69, 0x90, 0x34, 0xfc, 0xe1,
     0x85, 0x10, 0x5f, 0x8a,
     0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0xa2, 0xd8, 0x22, 0x50,
     0x74, 0xf9, 0x37, 0x83,
     0xe7, 0x6a, 0xf4, 0xe1, 0xd2, 0x84, 0xcb, 0x62, 0xe6, 0xca, 0x40, 0xdc,
     0x17, 0x5d, 0x73, 0x6b,
     0x8e, 0x25, 0x68, 0x11, 0x82, 0x3a, 0x40, 0x10, 0xb2, 0x21, 0x77, 0x6e,
     0x99, 0x8f, 0x4e, 0x1b,
     0xfc, 0x37, 0x35, 0xbd, 0x82, 0x2b, 0xa9, 0x5d, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x03,
     0x59, 0x65, 0xb8, 0x76, 0xad, 0x0b, 0x3d, 0x14, 0xa2, 0x42, 0x57, 0x20,
     0x6e, 0x56, 0xa1, 0x46,
     0xe9, 0xbd, 0xa2, 0x39, 0x01, 0x09, 0xb1, 0xbd, 0x1a, 0x60, 0x16, 0xfa,
     0xd5, 0x08, 0x7b, 0x2e,
     0x49, 0x35, 0x72, 0x00, 0x97, 0xe8, 0x20, 0x7b, 0x27, 0x92, 0xb4, 0x68,
     0xd2, 0x58, 0x7e, 0x8c,
     0x27, 0x6e, 0x14, 0x02, 0x6e, 0x08, 0xfa, 0x62, 0x08, 0x8b, 0x0c, 0x16,
     0xd8, 0x50, 0xd6, 0x52,
     0x26, 0xae, 0xc6, 0x08, 0xaf, 0x01, 0xbf, 0x5f, 0x83, 0x74, 0x71, 0x69,
     0xa6, 0xe3, 0xc6, 0xfb,
     0x92, 0x7d, 0x76, 0x97, 0x03, 0xdb, 0x64, 0xcd, 0xce, 0x85, 0x9f, 0x40,
     0x7a, 0x6b, 0xa9, 0xc7,
     0xc5, 0x6e, 0xdc, 0x64, 0x03, 0x6a, 0xc7, 0xde, 0x08, 0x70, 0xfd, 0x37,
     0x25, 0xeb, 0x3d, 0x6b,
     0x3f, 0x3c, 0x0f, 0x0d, 0x37, 0x12, 0x31, 0xdf, 0x01, 0xab, 0xd0, 0x99,
     0x9d, 0x6b, 0x7b, 0x6a,
     0xb8, 0xad, 0xc4, 0xa9, 0xd2, 0x5d, 0xbb, 0xc2, 0xe4, 0x27, 0xc0, 0xf5,
     0x3b, 0x67, 0xf6, 0xb9,
     0xbb, 0x96, 0xf7, 0x66, 0xf0, 0xb4, 0xbb, 0x84, 0x86, 0x25, 0x07, 0xf2,
     0xc2, 0xbf, 0xcf, 0x36,
     0x70, 0x8f, 0xbf, 0x97, 0x56, 0xc8, 0x74, 0xdc, 0x99, 0x11, 0xad, 0x9d,
     0x8d, 0x94, 0x10, 0xd8,
     0xfa, 0x0d, 0xc5, 0x94, 0x0e, 0x92, 0x0f, 0x57, 0xe7, 0xfb, 0x85, 0x92,
     0x29, 0x55, 0xa7, 0xbd,
     0xf0, 0x01, 0x9f, 0x4f, 0x50, 0xa7, 0x81, 0xb8, 0xb8, 0xf9, 0x57, 0xc5,
     0xe4, 0x5a, 0x22, 0x29,
     0x3d, 0x91, 0xea, 0xce, 0xda, 0x30, 0x44, 0xf8, 0x33, 0x17, 0x94, 0xef,
     0x05, 0x86, 0xe0, 0xf7,
     0xc1, 0x7a, 0x47, 0x24, 0x40, 0x85, 0xf7, 0xfd, 0x09, 0x3f, 0x22, 0x79,
     0x43, 0x02, 0xba, 0xa4,
     0x1f, 0xb0, 0x8d, 0xae, 0x74, 0x82, 0x5b, 0x21, 0x9c, 0xd4, 0xcb, 0x7b,
     0x2c, 0xba, 0x61, 0xe6,
     0x7f, 0xe8, 0x23, 0x30, 0x3a, 0x10, 0x81, 0xda, 0x3b, 0x5e, 0xcb, 0xf0,
     0x6a, 0x7e, 0x2d, 0x6f,
     0x40, 0x70, 0x3a, 0xf3, 0x55, 0x0a, 0xbe, 0x73, 0x3d, 0x43, 0xf8, 0xce,
     0x74, 0x2d, 0xb6, 0x79,
     0x38, 0x7e, 0x7c, 0x4e, 0xd3, 0x2d, 0x4b, 0xf8, 0xb4, 0xb6, 0x01, 0x6b,
     0xf3, 0x4a, 0xf9, 0x41,
     0x99, 0x07, 0xa4, 0x4c, 0xb2, 0x5a, 0x6d, 0xd7, 0x89, 0x0a, 0x0b, 0x06,
     0x3b, 0x90, 0x0d, 0xe6,
     0x0d, 0x36, 0x4d, 0xcf, 0xdb, 0xdb, 0xb7, 0x52, 0x12, 0x8b, 0x6a, 0x15,
     0x28, 0x5c, 0x30, 0xd7,
     0x0c, 0xd2, 0xe2, 0x1b, 0xe1, 0x69, 0x5a, 0xa8, 0x47, 0x5d, 0x14, 0x7e,
     0x74, 0xf2, 0x90, 0x85,
     0xb9, 0x8c, 0x33, 0x0f, 0x84, 0xd1, 0x3e, 0x6f, 0x32, 0x0b, 0x7e, 0x13,
     0xea, 0x5e, 0x88, 0x00,
     0x73, 0xc6, 0x47, 0x73, 0xa7, 0x7f, 0xd0, 0x67, 0x5c, 0x83, 0xff, 0x25,
     0xed, 0xec, 0x69, 0x50,
     0xc8, 0x20, 0xa7, 0x7f, 0xef, 0x33, 0xdf, 0x9a, 0x50, 0x53, 0xff, 0xab,
     0x58, 0x63, 0xdb, 0xd2,
     0x25, 0x17, 0x6f, 0x39, 0xbe, 0xb6, 0x22, 0x16, 0x35, 0xdf, 0x01, 0x83,
     0x8a, 0x69, 0x83, 0x0a,
     0x20, 0xe9, 0x11, 0x54, 0x77, 0x9e, 0x91, 0x10, 0xad, 0x00, 0x17, 0x8b,
     0x91, 0x4f, 0xcd, 0x88,
     0x6f, 0x41, 0x41, 0x06, 0xf5, 0x92, 0xbd, 0x2b, 0x31, 0x5e, 0xaf, 0xfc,
     0x04, 0xc9, 0xc1, 0x88,
     0x76, 0xd7, 0xb7, 0x83, 0x9c, 0xd2, 0xf4, 0xba, 0xa5, 0x61, 0xbf, 0x57,
     0xa7, 0x04, 0x26, 0xce,
     0x19, 0xc4, 0x57, 0xcb, 0x8d, 0x86, 0x26, 0xeb, 0x28, 0xd9, 0xb4, 0x0a,
     0x9b, 0x6b, 0x69, 0x5f,
     0xf2, 0x62, 0x5b, 0x5a, 0xab, 0xde, 0x91, 0x29, 0xbd, 0x53, 0x0b, 0xb3,
     0x42, 0xe2, 0x61, 0xf4,
     0x0f, 0xaa, 0x6e, 0xe6, 0x0b, 0xb4, 0x8b, 0x4b, 0x53, 0x94, 0xe0, 0x46,
     0x38, 0x13, 0x93, 0x11,
     0x30, 0xb8, 0x64, 0xbf, 0x9f, 0x6b, 0x43, 0x07, 0x95, 0xfc, 0x48, 0xbb,
     0x2a, 0x4f, 0xb3, 0xfc,
     0xb8, 0x26, 0x4c, 0x17, 0x5d, 0x49, 0x1d, 0x0d, 0x47, 0x12, 0x30, 0xbd,
     0x23, 0xf4, 0xfc, 0x86,
     0x09, 0x93, 0xf1, 0xf7, 0x89, 0x7d, 0x4f, 0x43, 0x39, 0xdb, 0xa5, 0x4e,
     0x86, 0x03, 0x9c, 0x8a,
     0xb9, 0x9f, 0xbf, 0xd8, 0x03, 0x30, 0x92, 0xc2, 0x39, 0x3e, 0xaa, 0x88,
     0x6c, 0x7c, 0x83, 0x95,
     0x13, 0x26, 0xf1, 0x5c, 0x62, 0xc8, 0x66, 0x12, 0xe3, 0x8e, 0x91, 0xc0,
     0x11, 0x93, 0x72, 0xed,
     0x16, 0xa5, 0x0a, 0xf6, 0x3a, 0xa8, 0x52, 0xea, 0x4f, 0x1a, 0x9a, 0x33,
     0xe0, 0xfc, 0x56, 0x1f,
     0x8a, 0x99, 0xd2, 0x47, 0x93, 0x34, 0x7f, 0xea, 0xdf, 0x08, 0xac, 0x58,
     0x3f, 0xe4, 0x7d, 0xb1,
     0xb7, 0x39, 0x5b, 0x9c, 0xc4, 0x52, 0x41, 0xc4, 0x63, 0xf1, 0xfa, 0xc9,
     0x22, 0xea, 0x93, 0x32,
     0xca, 0x2c, 0x0f, 0x75, 0xd9, 0x59, 0xbc, 0x33, 0xde, 0xf4, 0xdd, 0x69,
     0x94, 0xd3, 0xa0, 0xf3,
     0x0f, 0xe7, 0x0e, 0x66, 0xb4, 0x65, 0x45, 0x73, 0xce, 0x1c, 0x3e, 0xe3,
     0x32, 0x45, 0x85, 0x02,
     0x94, 0x33, 0xe5, 0xc6, 0x84, 0xda, 0xce, 0x2f, 0x6c, 0x5a, 0x35, 0xc9,
     0xa9, 0x45, 0x63, 0x32,
     0xd9, 0x91, 0x8b, 0x62, 0x60, 0x45, 0xab, 0x59, 0x42, 0x91, 0x60, 0x7c,
     0xae, 0xf6, 0xab, 0x87,
     0xce, 0x81, 0xd4, 0x33, 0x2f, 0xce, 0xf4, 0x04, 0x17, 0x74, 0xc6, 0x6a,
     0x89, 0xc5, 0x05, 0x79,
     0x2e, 0x28, 0xd0, 0xf1, 0x08, 0x56, 0x70, 0x8b, 0xc3, 0xb9, 0x9d, 0xc2,
     0xfb, 0x96, 0x88, 0xe3,
     0x1d, 0xba, 0x32, 0xfa, 0xba, 0x62, 0x70, 0x74, 0x37, 0x86, 0x1a, 0x86,
     0xe8, 0x66, 0xb5, 0x7b,
     0x1b, 0x40, 0x79, 0x61, 0xbc, 0x87, 0x9b, 0xeb, 0x88, 0xb3, 0x45, 0xbc,
     0x3a, 0xed, 0x4b, 0xaa,
     0x91, 0xe5, 0x71, 0xe2, 0xab, 0x39, 0x9a, 0x52, 0x63, 0xba, 0xcc, 0x8d,
     0xc5, 0x50, 0x84, 0xa3,
     0xcd, 0x16, 0x02, 0xab, 0x0c, 0xdb, 0xb5, 0x8e, 0xa3, 0xa8, 0x05, 0x43,
     0x22, 0xf2, 0x59, 0xc8,
     0x19, 0xee, 0x24, 0x06, 0xae, 0x4a, 0x80, 0xa2, 0xc7, 0xba, 0xff, 0x27,
     0x34, 0x07, 0x6f, 0x4d,
     0x47, 0xe6, 0xfc, 0x02, 0x4a, 0x1a, 0x8d, 0xad, 0x4d, 0x42, 0x7f, 0x8b,
     0x48, 0x46, 0xbb, 0x5f,
     0xb5, 0x66, 0xdf, 0x07, 0x46, 0xf5, 0x20, 0x52, 0x64, 0xd3, 0x5f, 0xdc,
     0x95, 0xcd, 0xaf, 0x4b,
     0xfa, 0xfd, 0x3b, 0xe5, 0x9d, 0x5d, 0x5d, 0xca, 0x72, 0x13, 0xae, 0x1b,
     0x46, 0x84, 0xd8, 0xec,
     0x7f, 0x8b, 0xc2, 0x53, 0xa6, 0x36, 0x6c, 0x4a, 0x58, 0x2e, 0xf7, 0xe1,
     0x6a, 0xee, 0xf7, 0x4b,
     0xd7, 0xb7, 0x61, 0x19, 0x27, 0xc3, 0xd9, 0x31, 0x08, 0x45, 0xf5, 0xc9,
     0x9d, 0xda, 0xaf, 0xec,
     0xc1, 0x1f, 0x16, 0x76, 0x6a, 0xde, 0xc6, 0x62, 0xc5, 0x83, 0xcd, 0x1f,
     0x49, 0x96, 0xd1, 0xe8,
     0xa8, 0x2a, 0xf5, 0x89, 0x94, 0x81, 0xcd, 0x1f, 0x14, 0x31, 0xc0, 0x06,
     0x40, 0x3f, 0x74, 0x0e,
     0xf3, 0x0f, 0x3f, 0x2b, 0xa3, 0x7c, 0x62, 0xe4, 0x23, 0x1b, 0x1e, 0xc8,
     0x28, 0xbe, 0x3c, 0xd6,
     0xf5, 0xc6, 0x19, 0x2f, 0x25, 0xb0, 0x87, 0x21, 0xff, 0x0e, 0xa7, 0xa9,
     0xee, 0xbe, 0x97, 0x41,
     0x70, 0x58, 0xcc, 0xd9, 0xe0, 0x04, 0xdb, 0x97, 0x70, 0x01, 0x2e, 0x8d,
     0x6c, 0x86, 0x21, 0x36,
     0x7b, 0x4c, 0xf0, 0xac, 0xd4, 0xc4, 0x5d, 0x37, 0x25, 0x22, 0x89, 0x62,
     0xd8, 0x28, 0x5a, 0x6c,
     0xdd, 0xd9, 0xe7, 0xfc, 0xb5, 0x31, 0x82, 0x15, 0x5a, 0x33, 0xe3, 0x28,
     0x65, 0x11, 0x3e, 0x7b,
     0x6f, 0xe4, 0xf3, 0xad, 0x4f, 0xba, 0x86, 0xe1, 0xc6, 0x1f, 0x29, 0x82,
     0x07, 0x27, 0xdf, 0xd4,
     0x15, 0x2a, 0x49, 0xac, 0x96, 0x3c, 0xb8, 0xed, 0x3e, 0x0f, 0xdb, 0xb8,
     0xb8, 0xe6, 0x9b, 0xbb,
     0xb7, 0xb3, 0x7b, 0xba, 0x89, 0x57, 0x66, 0x8b, 0xc5, 0x74, 0x47, 0x92,
     0x62, 0x6b, 0x4a, 0x45,
     0x9d, 0xab, 0x80, 0xe0, 0x44, 0x2c, 0xa5, 0x6c, 0xb2, 0x8e, 0x21, 0xa3,
     0x31, 0xee, 0xf5, 0xa9,
     0xd1, 0x92, 0x66, 0x2e, 0x3f, 0x2c, 0xdd, 0x96, 0xbc, 0x09, 0x34, 0xb1,
     0x65, 0xb3, 0x97, 0x08,
     0xc6, 0x46, 0x1a, 0x25, 0xe4, 0x40, 0xd1, 0x1f, 0xd9, 0xe1, 0x46, 0xa7,
     0x28, 0x0c, 0xad, 0x5f,
     0x0d, 0x5d, 0x83, 0x00, 0xc4, 0x53, 0x3c, 0xc0, 0xa0, 0xe4, 0x3d, 0x8c,
     0x1e, 0xdf, 0xe0, 0x7c,
     0xc3, 0x79, 0x60, 0x35, 0x48, 0xd4, 0x02, 0x28, 0xa1, 0xae, 0x4a, 0xe1,
     0xab, 0x76, 0x7b, 0xf6,
     0xb3, 0x0a, 0x57, 0x35, 0xf7, 0xbf, 0x97, 0x3c, 0xc7, 0x3b, 0x89, 0xa0,
     0x82, 0x43, 0xaa, 0xa9,
     0xc1, 0x14, 0x1c, 0xdb, 0x1e, 0x65, 0x75, 0xc8, 0xe2, 0x99, 0xba, 0x8c,
     0x0e, 0xa7, 0xe9, 0x3a,
     0x4e, 0x3a, 0x4c, 0xe4, 0x58, 0x1a, 0xa9, 0x35, 0xa9, 0x6a, 0xc2, 0x26,
     0xcd, 0x1d, 0x5f, 0x06,
     0xd6, 0x66, 0x34, 0x49, 0x33, 0xa2, 0x27, 0x21, 0x5f, 0x01, 0x52, 0xad,
     0xd9, 0x21, 0xc8, 0x08,
     0x1f, 0xd8, 0x0b, 0x27, 0x02, 0xb4, 0x0f, 0xc9, 0x32, 0x52, 0x58, 0xea,
     0x87, 0x40, 0x63, 0x61,
     0xda, 0xa4, 0x97, 0xca, 0x67, 0xc7, 0xbd, 0xa3, 0x68, 0x7a, 0xc1, 0xa0,
     0xb6, 0x86, 0x98, 0x1d,
     0x92, 0xa0, 0xad, 0xe0, 0x30, 0x96, 0xba, 0xd5, 0x27, 0x9f, 0x97, 0x9d,
     0xdf, 0xf0, 0xbf, 0x31,
     0xc8, 0xfa, 0x5a, 0x20, 0x56, 0x22, 0xd2, 0x72, 0x16, 0x34, 0x78, 0x28,
     0xba, 0x08, 0xb8, 0x40,
     0x40, 0x3b, 0x6d, 0xdf, 0x0f, 0x47, 0xeb, 0x45, 0x38, 0x64, 0x79, 0x54,
     0xf7, 0xc0, 0xcb, 0x51,
     0x1d, 0xa6, 0x69, 0xcb, 0xf7, 0x7d, 0x6c, 0x8c, 0x15, 0x0f, 0x39, 0xe2,
     0xb9, 0x7d, 0xea, 0x26,
     0x9f, 0xdc, 0xda, 0xd4, 0x1e, 0x54, 0xce, 0xcc, 0xe5, 0x09, 0x39, 0x0e,
     0xb8, 0xe4, 0xf2, 0x92,
     0x0a, 0xbf, 0xaa, 0x4e, 0x15, 0xb7, 0xdc, 0x94, 0x2d, 0x47, 0x58, 0x64,
     0x1c, 0xfd, 0xb5, 0x2f,
     0x2f, 0xff, 0x3e, 0xaa, 0xab, 0x4b, 0xc0, 0xf1, 0xd8, 0x26, 0xdd, 0xdd,
     0x19, 0x94, 0x42, 0xa5,
     0xca, 0xf6, 0x8d, 0x94, 0x8a, 0x5c, 0x02, 0xa8, 0x85, 0x1a, 0x2c, 0xcb,
     0x3d, 0x36, 0x27, 0x10,
     0xbd, 0xf8, 0x32, 0x27, 0xa4, 0x9e, 0x53, 0xac, 0xc0, 0xd7, 0xfb, 0x13,
     0xf4, 0x5f, 0x6b, 0x7b,
     0x5c, 0x58, 0xe8, 0x12, 0x62, 0xce, 0x1c, 0x13, 0x3a, 0x1e, 0x19, 0xfc,
     0xd3, 0xf0, 0xa7, 0x8f,
     0x81, 0xcd, 0x90, 0x1a, 0x40, 0x53, 0x0a, 0x91, 0xd7, 0xe8, 0x7c, 0x2e,
     0xec, 0xcb, 0x58, 0x96,
     0x05, 0xa3, 0x90, 0x8c, 0xb7, 0x70, 0x28, 0x3f, 0x6c, 0x80, 0xf1, 0x73,
     0x23, 0xd7, 0x20, 0xc1,
     0x08, 0x5d, 0x09, 0x1b, 0x27, 0x40, 0xe1, 0x39, 0xf7, 0xc2, 0xdc, 0x7c,
     0x42, 0x19, 0xc3, 0x51,
     0xd5, 0x44, 0x0b, 0x21, 0x6b, 0x89, 0x10, 0xca, 0xf9, 0x30, 0x75, 0x47,
     0xde, 0x9e, 0x18, 0x44,
     0x92, 0x17, 0xb1, 0xbc, 0x76, 0xbd, 0xbb, 0xff, 0x4d, 0xf6, 0x4f, 0x17,
     0x16, 0xc4, 0x1c, 0xa3,
     0x15, 0x01, 0x4a, 0x14, 0xde, 0x70, 0x6e, 0x8a, 0x2a, 0x75, 0xae, 0xbd,
     0x52, 0x10, 0xf6, 0x5c,
     0x3d, 0x3e, 0x03, 0xbc, 0x54, 0xc6, 0x5f, 0x4a, 0x28, 0xf5, 0xd5, 0x95,
     0x4f, 0x19, 0x9a, 0x6e,
     0xdc, 0xb7, 0xed, 0x80, 0x49, 0x0d, 0xbe, 0xb0, 0x6e, 0x78, 0x18, 0xc5,
     0x61, 0x83, 0x44, 0x2b,
     0x01, 0x2d, 0x35, 0x6b, 0x62, 0x7c, 0xde, 0x0b, 0x79, 0xfa, 0x6e, 0xd6,
     0x11, 0x02, 0x01, 0x9a,
     0x9b, 0x24, 0x83, 0x1d, 0x67, 0xa6, 0x75, 0xef, 0x69, 0x01, 0x0f, 0xc7,
     0x38, 0x7b, 0xf0, 0xfd,
     0x5d, 0xc7, 0xa2, 0xa6, 0x47, 0xdc, 0xcd, 0xb2, 0x20, 0xd5, 0xb2, 0x05,
     0x86, 0x6b, 0x56, 0xe5,
     0x68, 0x36, 0x9b, 0x02, 0xbb, 0xab, 0xda, 0x5d, 0x39, 0xa9, 0xce, 0xe5,
     0x66, 0x25, 0x91, 0x9d,
     0x93, 0xbd, 0xec, 0xba, 0x42, 0x6a, 0x08, 0x66, 0x01, 0xd1, 0xd3, 0x95,
     0x5b, 0xd1, 0x03, 0xa4,
     0xd3, 0x1d, 0x0f, 0xb3, 0x12, 0x02, 0x32, 0xf8, 0x61, 0xc7, 0x53, 0x87,
     0xda, 0x8a, 0xf4, 0x90,
     0x67, 0xa3, 0xe7, 0x6b, 0xc4, 0x2e, 0x38, 0xab, 0x43, 0xe4, 0x87, 0x66,
     0xc4, 0x9c, 0xcf, 0x79,
     0xd2, 0x83, 0x1a, 0xd1, 0x31, 0x31, 0x16, 0xfa, 0x15, 0xa0, 0x80, 0x49,
     0xb1, 0x98, 0x80, 0xc0,
     0xff, 0xad, 0x85, 0xbc, 0xdb, 0x03, 0xcd, 0x14, 0xf6, 0x90, 0x7e, 0x52,
     0xeb, 0x2b, 0xb2, 0x67,
     0x26, 0xf6, 0xbe, 0xa5, 0xcd, 0xbb, 0xa2, 0xd3, 0x21, 0x76, 0xae, 0xec,
     0xfc, 0xf9, 0x77, 0x6f,
     0x8d, 0xd4, 0x13, 0x02, 0xe3, 0x9f, 0x3a, 0x04, 0x36, 0x68, 0x78, 0xe9,
     0x86, 0x78, 0x72, 0xe9,
     0xf8, 0x95, 0xda, 0x4a, 0xdc, 0x73, 0x11, 0x83, 0xda, 0xbe, 0x99, 0x3f,
     0x44, 0x0d, 0x06, 0x94,
     0x35, 0x2f, 0x78, 0xfa, 0x4e, 0x17, 0x99, 0xfd, 0x92, 0x92, 0x45, 0xf3,
     0xb3, 0x2d, 0xad, 0xbb,
     0x05, 0x48, 0xd2, 0xbe, 0x3f, 0x0b, 0x7e, 0x94, 0xe2, 0x50, 0xf0, 0xed,
     0x7a, 0xd4, 0x2a, 0x4b,
     0x1b, 0x1c, 0xd7, 0x64, 0xb6, 0x17, 0x25, 0xce, 0xe6, 0x7c, 0x0a, 0x1a,
     0x88, 0x00, 0xe2, 0x8f,
     0x08, 0x9d, 0x7e, 0x7b, 0xe7, 0xbf, 0x1d, 0x39, 0x40, 0xa1, 0xb0, 0x0e,
     0x5d, 0x49, 0x98, 0x33,
     0xad, 0x60, 0x3e, 0x88, 0xdd, 0x1c, 0xb8, 0xd0, 0xb3, 0xbd, 0x2e, 0x12,
     0xb8, 0xa2, 0x99, 0xc7,
     0xe4, 0x03, 0xa9, 0x9a, 0xf4, 0xc4, 0x2f, 0x16, 0x34, 0xc9, 0xb3, 0xc8,
     0x07, 0x7f, 0x23, 0x00,
     0xd3, 0x1d, 0x37, 0x5a, 0x28, 0x16, 0xce, 0xba, 0xac, 0x26, 0x0f, 0xa5,
     0x61, 0x48, 0x31, 0x91,
     0xd8, 0x1c, 0xff, 0x54, 0xf4, 0x94, 0xa5, 0xb3, 0x2d, 0x6e, 0x4d, 0x58,
     0x56, 0x27, 0xe1, 0x34,
     0x47, 0xba, 0x8b, 0x0b, 0x43, 0x36, 0x0c, 0xd6, 0x64, 0x59, 0xbc, 0x89,
     0xf2, 0x64, 0x17, 0x0e,
     0x54, 0x3d, 0x4e, 0x92, 0x57, 0xe0, 0xf2, 0x6d, 0x82, 0xc3, 0xe1, 0x30,
     0xa9, 0x35, 0x0a, 0x59,
     0x81, 0xca, 0xae, 0xf3, 0x35, 0x86, 0x52, 0x96, 0xbe, 0x02, 0x72, 0xca,
     0x4f, 0x47, 0xee, 0xdd,
     0x98, 0x1f, 0x19, 0x4d, 0x61, 0x78, 0xb3, 0xb4, 0x06, 0x54, 0x06, 0xc8,
     0x7a, 0x9c, 0x34, 0x51,
     0x7c, 0x89, 0xb7, 0xbb, 0x81, 0x79, 0x16, 0x10, 0x49, 0x42, 0x42, 0x28,
     0xb9, 0x37, 0x25, 0xb4,
     0xc0, 0xee, 0x33, 0xe0, 0x79, 0xd3, 0xec, 0x5b, 0x7c, 0x51, 0x9c, 0x47,
     0x5b, 0x24, 0x88, 0x95,
     0xcc, 0xe5, 0x3d, 0xcf, 0xed, 0xef, 0xc7, 0x5e, 0xc7, 0x73, 0xc7, 0x0e,
     0x14, 0xdb, 0xd3, 0x9f,
     0x80, 0xa8, 0xe1, 0xd9, 0x9d, 0x39, 0x26, 0x53, 0x50, 0x6d, 0x99, 0x1e,
     0xcb, 0x88, 0x53, 0x04,
     0xed, 0x54, 0x7b, 0x5c, 0x7d, 0xa7, 0xab, 0x38, 0xd9, 0xb1, 0x61, 0x4c,
     0x22, 0x46, 0x32, 0x40,
     0xf0, 0xe4, 0xbe, 0x90, 0x28, 0x79, 0x98, 0x13, 0x15, 0xa9, 0x61, 0x02,
     0x6d, 0x7c, 0x42, 0x30,
     0x74, 0x82, 0x00, 0x75, 0xa1, 0x34, 0x8f, 0xa9, 0x55, 0x82, 0x43, 0x12,
     0x93, 0x00, 0x22, 0x10,
     0xc4, 0x6b, 0x10, 0x29, 0x49, 0x0d, 0x5c, 0x0c, 0x2f, 0x6b, 0x7c, 0x95,
     0x96, 0x4a, 0xef, 0x23,
     0x7d, 0x32, 0x44, 0x10, 0x29, 0xad, 0x1e, 0x9b, 0xd2, 0xe4, 0x0a, 0x03,
     0xf2, 0x1a, 0x52, 0xf2,
     0xcb, 0x26, 0x5c, 0xd4, 0x8c, 0x34, 0xb2, 0x18, 0x01, 0xc1, 0x49, 0xbd,
     0x84, 0xa3, 0xf1, 0xef,
     0xe2, 0x63, 0xff, 0xff, 0x36, 0x7b, 0x9a, 0xcc, 0x13, 0x20, 0xde, 0xc0,
     0x83, 0x0c, 0x55, 0x05,
     0x98, 0x05, 0x59, 0x91, 0xeb, 0x90, 0xfa, 0x14, 0xcb, 0x4e, 0xd5, 0x05,
     0x10, 0x01, 0xd4, 0xce,
     0x43, 0x06, 0x16, 0x52, 0x79, 0x17, 0xac, 0xa9, 0xbc, 0xcf, 0xc3, 0xe5,
     0x4d, 0x98, 0x5f, 0xd9,
     0xef, 0x0e, 0x91, 0x5f, 0xb8, 0x2f, 0xe7, 0xd1, 0xf5, 0x5c, 0x64, 0x10,
     0xf3, 0x6b, 0x27, 0xe5,
     0x77, 0x7d, 0xdf, 0xf7, 0x52, 0xc4, 0x60, 0x2f, 0xa8, 0x9e, 0xad, 0xcc,
     0x84, 0xfa, 0xe9, 0x0c,
     0x54, 0x7b, 0x71, 0x67, 0x4c, 0x0d, 0xf2, 0x12, 0xc3, 0x49, 0xdb, 0xc7,
     0xba, 0x97, 0x61, 0xb1,
     0xf4, 0x74, 0x4a, 0x2f, 0x5e, 0xab, 0x58, 0xb0, 0x7c, 0x50, 0xe7, 0x02,
     0xfe, 0x83, 0x21, 0x3d,
     0x00, 0x00, 0x00, 0x06, 0x81, 0x68, 0x9b, 0x85, 0x97, 0x66, 0x7e, 0x18,
     0x26, 0xbf, 0x19, 0x16,
     0xaf, 0x25, 0x5a, 0xa6, 0x7d, 0xf0, 0x74, 0x81, 0xe2, 0x74, 0x7d, 0xdf,
     0xa0, 0xa3, 0x6e, 0xeb,
     0xd5, 0x99, 0x1f, 0x3a, 0x7d, 0x24, 0xfb, 0x93, 0xf3, 0x82, 0x6b, 0x31,
     0x4c, 0xa2, 0x9e, 0x93,
     0xde, 0xf5, 0x32, 0x9d, 0x52, 0x5c, 0xce, 0x2a, 0xfe, 0xfd, 0x7e, 0x7b,
     0xfe, 0x36, 0xbf, 0x40,
     0x39, 0xec, 0x0c, 0x99, 0x39, 0x3e, 0x67, 0xdb, 0xaa, 0x42, 0x1a, 0x75,
     0x58, 0xfa, 0x25, 0x3c,
     0x04, 0xe5, 0xc8, 0xac, 0x87, 0xd2, 0x54, 0x70, 0x0e, 0x5c, 0x24, 0xf7,
     0xa0, 0xc1, 0xc6, 0x48,
     0x0d, 0xf5, 0x14, 0x44, 0x28, 0xba, 0x12, 0x4b, 0xbc, 0x00, 0x74, 0xed,
     0xb2, 0x86, 0x19, 0x6a,
     0xfa, 0xa0, 0xfa, 0xb5, 0xc5, 0x49, 0x25, 0xde, 0x73, 0x07, 0x20, 0x5a,
     0x87, 0x79, 0x6f, 0x7f,
     0xb0, 0xaa, 0xf8, 0x53, 0xa5, 0xf7, 0x2a, 0xa9, 0x7b, 0x1a, 0x1c, 0x8a,
     0xa8, 0x46, 0x54, 0xd5,
     0x4a, 0x45, 0x4c, 0xc8, 0x66, 0x6c, 0xf5, 0xc1, 0xa3, 0x17, 0x12, 0x14,
     0x81, 0x08, 0x75, 0x6e,
     0x44, 0x32, 0xad, 0x74, 0x68, 0x4c, 0xfb, 0xfb, 0xc4, 0x66, 0x0a, 0x9b,
     0xae, 0xab, 0xd1, 0xcd,
     0x23, 0xae, 0x07, 0xab, 0x11, 0x45, 0x6e, 0xc9, 0x2d, 0xfa, 0xaa, 0x64,
     0x26, 0x13, 0x8d, 0x7e,
     0xae, 0x49, 0x5d, 0x85, 0x4c, 0x52, 0x2c, 0xe2, 0xf6, 0x7a, 0x37, 0xdc,
     0x80, 0xc1, 0x4c, 0x29,
     0xb2, 0x40, 0xd1, 0x2f, 0x7a, 0x25, 0x44, 0x3a, 0x17, 0x27, 0xf8, 0xc8,
     0xab, 0x33, 0x4d, 0xac,
     0x3f, 0xf6, 0x1a, 0x0c, 0xdd, 0xf5, 0x7b, 0xf5, 0x12, 0x10, 0x09, 0x6e,
     0xba, 0xc7, 0x37, 0x05,
     0x1d, 0x23, 0xe1, 0xdd, 0xe3, 0x97, 0xa1, 0x42, 0x9d, 0x0f, 0xe5, 0xa3,
     0x67, 0xc5, 0xbf, 0x18,
     0x81, 0x51, 0xe7, 0x53, 0xe6, 0x97, 0x85, 0x56, 0x84, 0x43, 0xfd, 0xf3,
     0x8f, 0x74, 0xfe, 0x78,
     0xfc, 0x3d, 0x03, 0xd3, 0x24, 0x2c, 0x50, 0xb0, 0x33, 0x70, 0x34, 0x46,
     0xf5, 0xd5, 0xe7, 0xc1,
     0x51, 0xb4, 0xc6, 0x4a, 0xe3, 0xce, 0x29, 0x42, 0xc1, 0x6e, 0x32, 0xef,
     0xf9, 0xeb, 0x48, 0x1e,
     0x04, 0x0e, 0xfd, 0x75, 0xe2, 0x9f, 0x4b, 0xcc, 0xb4, 0xf6, 0x7b, 0x79,
     0x2f, 0xdc, 0xc7, 0xfc,
     0x00, 0xac, 0x47, 0x1f,};

const test_vector vector_20_2 = {
    .name = "hss_ref_20_2",
    .key = hss_pubKey_20_2,
    .keyLen = sizeof(hss_pubKey_20_2),
    .sig = hss_sig_20_2,
    .sigLen = sizeof(hss_sig_20_2),
    .msg = hss_msg_20_2,
    .msgLen = sizeof(hss_msg_20_2)};
#ifdef __cplusplus
}
#endif

#endif /* _QUARK_REF_VEC_H_ */
