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
 *  Description : XMSS-MT reference vector for KAT.
 */

#ifndef _QUARK_XMSSMT_REF_VEC_40_2_H_
#define _QUARK_XMSSMT_REF_VEC_40_2_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "test_vector.h"

const uint8_t pk_mt_40_2[] =
    {0x03, 0x00, 0x00, 0x00, 0xc5, 0x3a, 0xdc, 0x22, 0x99, 0xdd, 0x3f, 0x4a,
     0xad, 0x3d, 0x6e, 0x1d,
     0xae, 0x95, 0xc5, 0xbe, 0xc9, 0x67, 0xd3, 0x9d, 0x8a, 0x5c, 0xc4, 0x8b,
     0x8d, 0xda, 0x9c, 0x42,
     0x0b, 0xdf, 0x47, 0x82, 0xf9, 0x5d, 0x7e, 0x77, 0x15, 0x46, 0x42, 0x11,
     0xe2, 0xed, 0xe1, 0x1d,
     0x09, 0x81, 0x78, 0x53, 0xd5, 0x87, 0x74, 0xef, 0xa2, 0x3a, 0x2a, 0x1c,
     0x82, 0x05, 0x96, 0x6d,
     0x23, 0xfa, 0x50, 0x18,};

const uint8_t sig_mt_40_2[] =
    {0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0xe4, 0xcf, 0x66, 0xd7, 0x6d, 0xb6,
     0x5a, 0xb5, 0xfd, 0xbd,
     0xdb, 0xa0, 0x36, 0x0b, 0x97, 0x8f, 0x08, 0xa6, 0x0a, 0x59, 0x00, 0x65,
     0xd9, 0xd3, 0x0f, 0x0d,
     0x4a, 0x5f, 0x4a, 0xb1, 0x4f, 0x19, 0x1b, 0xdd, 0xd4, 0xe3, 0xaf, 0x3b,
     0xa9, 0xcd, 0x25, 0x6d,
     0x2c, 0xa3, 0xde, 0x02, 0xf1, 0x41, 0x4a, 0x89, 0x13, 0x8d, 0x95, 0x98,
     0xd2, 0x3f, 0x4f, 0x46,
     0x10, 0x95, 0x59, 0x27, 0x28, 0x1c, 0x38, 0x30, 0x7c, 0x9e, 0xac, 0x71,
     0x10, 0xef, 0x3d, 0xaa,
     0x97, 0xc4, 0xf1, 0x82, 0x13, 0x1a, 0x66, 0xad, 0xa9, 0x5f, 0x95, 0x73,
     0xd0, 0x7c, 0x54, 0x7a,
     0xcd, 0x9f, 0xbb, 0x87, 0x2b, 0x8a, 0x58, 0x80, 0x3d, 0x7e, 0xdd, 0xed,
     0x4c, 0x60, 0x57, 0x16,
     0xb7, 0xf1, 0x32, 0x97, 0x36, 0x4e, 0x11, 0xb9, 0x05, 0x40, 0x0e, 0x03,
     0x31, 0x67, 0xed, 0x01,
     0x14, 0x45, 0x9f, 0x00, 0x92, 0xe1, 0xc6, 0xb3, 0xa6, 0xdf, 0x97, 0x29,
     0x5c, 0x09, 0x0e, 0x01,
     0x01, 0x9a, 0x8f, 0x14, 0x0f, 0xe8, 0xbf, 0x44, 0xc1, 0x5c, 0x6f, 0x5a,
     0xaf, 0x81, 0x78, 0x74,
     0x02, 0x73, 0xa5, 0x74, 0xe6, 0x25, 0x09, 0x6d, 0xcc, 0xab, 0x87, 0x58,
     0x81, 0xb5, 0x0e, 0xdc,
     0x29, 0x25, 0x26, 0xfe, 0x85, 0x12, 0x44, 0x38, 0x26, 0x62, 0x69, 0xd5,
     0xde, 0x1d, 0x4f, 0x63,
     0xde, 0x28, 0x7d, 0x2e, 0x69, 0xaf, 0x61, 0xeb, 0xb5, 0xd3, 0x92, 0x12,
     0x19, 0xaf, 0xbb, 0x2f,
     0x63, 0x81, 0x26, 0x77, 0x52, 0xd4, 0x5c, 0x9a, 0x50, 0x8f, 0x47, 0x05,
     0x17, 0xe1, 0x92, 0xbd,
     0xe2, 0x05, 0x55, 0x01, 0x56, 0xa9, 0x83, 0x65, 0xe9, 0xea, 0xd7, 0xc3,
     0x70, 0x49, 0x41, 0x53,
     0x24, 0xad, 0xf6, 0x52, 0x97, 0x5f, 0xae, 0x76, 0x38, 0xc7, 0x57, 0x9f,
     0x11, 0xae, 0x25, 0x90,
     0x1b, 0xef, 0x45, 0xbc, 0x3e, 0x16, 0x7f, 0xa4, 0xff, 0xa0, 0x2d, 0x72,
     0xe9, 0xb8, 0xdc, 0xab,
     0x46, 0xe5, 0x45, 0xab, 0x4a, 0x44, 0x54, 0x2c, 0x92, 0xdd, 0xf4, 0x55,
     0xd3, 0x04, 0x10, 0x11,
     0xc8, 0xd2, 0x65, 0x61, 0x66, 0x94, 0x9b, 0x53, 0x9f, 0x09, 0xb9, 0x81,
     0xfc, 0xeb, 0xd5, 0x4a,
     0xc9, 0x74, 0x8e, 0x15, 0x23, 0xe5, 0x50, 0xc6, 0xf5, 0x2d, 0x37, 0xe8,
     0x85, 0xea, 0x35, 0x51,
     0x05, 0x34, 0x29, 0x63, 0xdc, 0x51, 0xc4, 0x7b, 0xa1, 0x61, 0x3c, 0xed,
     0x46, 0xa9, 0xa7, 0xfe,
     0x7a, 0x5f, 0x96, 0xd4, 0xff, 0xd0, 0x17, 0x8f, 0x85, 0xe6, 0x9e, 0xee,
     0x61, 0xf6, 0xa5, 0x47,
     0x08, 0x6c, 0x2a, 0x2a, 0xf7, 0x60, 0x4d, 0x46, 0x65, 0x5a, 0x68, 0xf8,
     0x1f, 0x95, 0xdf, 0xfb,
     0x49, 0xb3, 0x47, 0x58, 0x27, 0xae, 0xcb, 0x43, 0xe4, 0x0e, 0xf4, 0x95,
     0xe0, 0x0b, 0x79, 0x94,
     0x0e, 0x33, 0x15, 0xc9, 0x9c, 0x7f, 0x4c, 0x15, 0xc7, 0x7e, 0x10, 0x24,
     0xfa, 0xee, 0x36, 0x60,
     0xcd, 0x83, 0xbc, 0xd8, 0x86, 0x81, 0x9f, 0x05, 0x4c, 0x28, 0x00, 0x75,
     0x4d, 0xde, 0x60, 0x5d,
     0xfb, 0x24, 0x72, 0x61, 0x69, 0xfb, 0x9a, 0x78, 0xd5, 0x50, 0x79, 0xb9,
     0xe4, 0xcd, 0x88, 0x9c,
     0x92, 0x27, 0x18, 0xe5, 0x43, 0x54, 0x79, 0x9d, 0x20, 0x5b, 0xe5, 0x34,
     0xd1, 0xeb, 0xf0, 0x76,
     0xd7, 0xd6, 0x94, 0x1a, 0x3c, 0x82, 0x2f, 0x5b, 0x45, 0xc1, 0x57, 0xd9,
     0x4b, 0xa7, 0xdb, 0xa1,
     0x3f, 0x7d, 0x4a, 0x28, 0x6f, 0x4f, 0x74, 0x53, 0xc9, 0x38, 0xe0, 0x19,
     0xe7, 0x07, 0x79, 0x06,
     0x10, 0xb1, 0xe1, 0xe8, 0x31, 0x1a, 0xe2, 0xb5, 0xfc, 0x4c, 0x8e, 0xee,
     0x19, 0xc0, 0x33, 0xa1,
     0x94, 0x22, 0x9e, 0xf5, 0x7b, 0x94, 0x1e, 0xff, 0xad, 0xd8, 0x5a, 0x6f,
     0x02, 0xe7, 0x60, 0xe2,
     0x2d, 0x0a, 0x75, 0x32, 0xed, 0x24, 0x57, 0x1c, 0x21, 0xbd, 0xbe, 0x8d,
     0xc7, 0x25, 0xf9, 0xf6,
     0xfd, 0x27, 0x25, 0xd5, 0xc1, 0x2f, 0x98, 0xdc, 0xab, 0xa8, 0x08, 0x53,
     0x5e, 0x6d, 0xa1, 0x08,
     0xf7, 0x76, 0x24, 0xc5, 0x6b, 0x16, 0x29, 0xb9, 0x06, 0x9c, 0xdb, 0x0c,
     0xf1, 0xe1, 0x8f, 0x02,
     0xa3, 0xfd, 0xfa, 0xee, 0xe9, 0x5f, 0x89, 0x88, 0xf6, 0x46, 0x93, 0x2a,
     0xa4, 0x48, 0x63, 0xda,
     0x3a, 0xd4, 0x97, 0x4d, 0x2f, 0xe8, 0x0f, 0xd4, 0xa4, 0xad, 0x1b, 0xef,
     0x0a, 0x66, 0x7f, 0x80,
     0xdc, 0x2e, 0xb0, 0xfc, 0x14, 0xa1, 0xa2, 0xcf, 0xc0, 0x51, 0xb4, 0xb7,
     0xaf, 0x76, 0xd7, 0x14,
     0xe9, 0x3d, 0x12, 0x82, 0x52, 0x35, 0x86, 0x34, 0x01, 0x7a, 0x92, 0x9f,
     0x49, 0xec, 0x7c, 0xde,
     0x4e, 0x06, 0x59, 0xfc, 0x4a, 0x0b, 0x42, 0x2b, 0xe6, 0x17, 0xba, 0xb2,
     0x7d, 0xd4, 0xc9, 0x4d,
     0xe8, 0xef, 0x1f, 0x13, 0x94, 0x2c, 0x45, 0x05, 0x3d, 0xde, 0x64, 0x18,
     0xbf, 0xc8, 0xbc, 0xcf,
     0x5d, 0x0d, 0x98, 0x67, 0xe9, 0x99, 0x12, 0xb7, 0x68, 0x36, 0xb5, 0xad,
     0x99, 0xcc, 0x5c, 0xa2,
     0x4e, 0x13, 0xbc, 0x9c, 0x6b, 0x48, 0xa3, 0x97, 0xfa, 0xb3, 0x10, 0x53,
     0x89, 0x69, 0x4c, 0x8c,
     0x63, 0x04, 0x82, 0xdc, 0xdc, 0x5d, 0x11, 0x8a, 0x1c, 0x49, 0x70, 0xdd,
     0x5e, 0x6d, 0x03, 0xdf,
     0xaf, 0xbc, 0x46, 0x9f, 0xcc, 0x82, 0xa9, 0x1c, 0x54, 0x15, 0x3f, 0x21,
     0x91, 0x25, 0x0f, 0xfd,
     0xa1, 0x10, 0xf1, 0x19, 0x9c, 0x75, 0x98, 0x06, 0x94, 0x17, 0x24, 0xe0,
     0x7e, 0xaf, 0xd4, 0x94,
     0xcd, 0xea, 0x82, 0xad, 0xb0, 0xd1, 0x80, 0x91, 0x2f, 0x97, 0xd9, 0xe2,
     0xf0, 0x59, 0xac, 0xa6,
     0xc3, 0x4d, 0x51, 0x9a, 0x4a, 0x72, 0xc7, 0xb2, 0xcf, 0xd9, 0xe8, 0x30,
     0xad, 0xd3, 0xcf, 0x2d,
     0xa6, 0x1f, 0x46, 0xb2, 0x7e, 0x3a, 0xa4, 0xda, 0xe0, 0x78, 0x52, 0xa4,
     0x16, 0x88, 0x06, 0x71,
     0xaf, 0x9e, 0xba, 0xad, 0xd8, 0xbd, 0x6a, 0xab, 0x81, 0xc2, 0x34, 0x7e,
     0x82, 0x3a, 0x16, 0x98,
     0x71, 0x49, 0xe8, 0x7e, 0x7b, 0x56, 0x63, 0x97, 0xb4, 0x5d, 0xe9, 0x8a,
     0xf7, 0x88, 0x10, 0x24,
     0xe7, 0x37, 0x5e, 0x71, 0x3d, 0xb7, 0x1a, 0x20, 0x0f, 0x37, 0xea, 0x98,
     0xda, 0x20, 0xbc, 0xd9,
     0x23, 0xd5, 0x25, 0x36, 0xf0, 0x42, 0x5a, 0x06, 0x25, 0x28, 0x06, 0x25,
     0xfe, 0x3f, 0x1e, 0xa0,
     0x2c, 0x08, 0x3f, 0xf2, 0xb7, 0x44, 0x88, 0xa6, 0x10, 0x7f, 0x21, 0xab,
     0x0b, 0x82, 0xba, 0x1d,
     0x50, 0xa4, 0xbb, 0x93, 0x16, 0x4c, 0xe3, 0xbb, 0x66, 0x69, 0xba, 0xea,
     0x1c, 0x7d, 0xe7, 0x17,
     0x3e, 0x53, 0x64, 0x68, 0xca, 0x6c, 0x80, 0x09, 0x18, 0x87, 0x75, 0x29,
     0x2e, 0x16, 0x2b, 0x1b,
     0x5a, 0x55, 0x36, 0x1f, 0xba, 0x0b, 0x23, 0x00, 0xae, 0xba, 0xe0, 0x92,
     0x87, 0x53, 0x45, 0x01,
     0x12, 0xce, 0xaa, 0x6f, 0x65, 0xd1, 0xf1, 0x0f, 0xe2, 0x10, 0xcf, 0x5a,
     0xe0, 0x73, 0xb6, 0x77,
     0x59, 0x2b, 0x0b, 0xf6, 0xeb, 0x6c, 0xbb, 0xfa, 0x28, 0xd9, 0xaa, 0xc6,
     0xa3, 0xd9, 0x6a, 0x55,
     0xae, 0x8b, 0xda, 0x63, 0x76, 0x67, 0x98, 0x7c, 0xf6, 0x17, 0xa2, 0x30,
     0xb0, 0x5b, 0x6d, 0xba,
     0xb3, 0xee, 0x40, 0xbf, 0x20, 0x9c, 0x91, 0x32, 0x2a, 0x29, 0xab, 0x57,
     0xef, 0xab, 0x02, 0x87,
     0xc5, 0xef, 0x9a, 0x23, 0x3c, 0xc1, 0x8e, 0x2b, 0x49, 0xaa, 0xf4, 0xa1,
     0x65, 0x24, 0x8e, 0x9b,
     0x1e, 0xf0, 0x3b, 0x9f, 0x90, 0x86, 0xcf, 0xca, 0x9c, 0xdd, 0x9d, 0x0b,
     0x2c, 0x06, 0x04, 0xee,
     0x05, 0xb7, 0xc7, 0x15, 0x5d, 0xce, 0xf0, 0x9d, 0x9f, 0xa7, 0xd0, 0x23,
     0xe8, 0x41, 0x2e, 0xfb,
     0x13, 0x18, 0xe0, 0xf8, 0xc1, 0x76, 0x6f, 0x45, 0x32, 0xad, 0x26, 0x2d,
     0xb1, 0xf8, 0x1a, 0xaa,
     0xb0, 0xf1, 0xca, 0x5e, 0xc5, 0xc1, 0xbd, 0xd3, 0xf1, 0x15, 0xac, 0x51,
     0xca, 0x6f, 0x7e, 0xf7,
     0xfc, 0x1a, 0x65, 0x13, 0x81, 0xcd, 0xa2, 0x28, 0xf1, 0xbe, 0x37, 0x2d,
     0x15, 0x1e, 0x6f, 0xba,
     0xc5, 0x0a, 0xa8, 0xc7, 0x49, 0xe5, 0x77, 0x8a, 0x08, 0x2f, 0xe7, 0xe3,
     0x00, 0x4f, 0xb0, 0x61,
     0x95, 0xca, 0x11, 0xff, 0x3b, 0xc4, 0x97, 0xed, 0x9d, 0xc3, 0x6e, 0x2e,
     0x8e, 0x5d, 0x21, 0x7a,
     0xd9, 0x34, 0x10, 0xcf, 0xa4, 0x5f, 0x80, 0x95, 0xa5, 0x40, 0xe1, 0xb9,
     0x30, 0x3e, 0xd4, 0xed,
     0xe9, 0xb8, 0x11, 0xd8, 0x6f, 0xc2, 0xf8, 0xcc, 0x72, 0x17, 0xe9, 0x51,
     0x15, 0xbd, 0x53, 0x78,
     0xee, 0xda, 0x9b, 0xfd, 0x33, 0x74, 0x06, 0xb3, 0xfa, 0xc4, 0x37, 0x08,
     0x8f, 0x58, 0xb1, 0x0f,
     0xf9, 0x48, 0xcb, 0x50, 0x69, 0x34, 0x02, 0x7d, 0x6c, 0x4f, 0xd4, 0x96,
     0xc9, 0x71, 0x7d, 0x8b,
     0x18, 0x91, 0x37, 0x89, 0xb4, 0xf2, 0x62, 0x78, 0x5c, 0xb0, 0xe0, 0xf5,
     0x56, 0xcb, 0x3f, 0x32,
     0xdb, 0x31, 0x5a, 0xf2, 0x99, 0x61, 0xdf, 0x5a, 0xea, 0x23, 0xad, 0x3f,
     0xe8, 0x6d, 0x91, 0x0e,
     0x84, 0x44, 0xcc, 0xa1, 0x04, 0xdf, 0x88, 0xf7, 0xa0, 0xaa, 0x37, 0x8c,
     0xb2, 0x5e, 0x04, 0xe2,
     0xba, 0x0c, 0x62, 0x20, 0xa5, 0x55, 0xc4, 0x92, 0x5a, 0x1c, 0x9b, 0xf1,
     0xc6, 0x1b, 0xbc, 0x19,
     0xc6, 0xa5, 0xe2, 0x87, 0x78, 0xab, 0x58, 0x4b, 0x09, 0x2a, 0xc1, 0xd3,
     0x04, 0x98, 0x1e, 0x73,
     0xe4, 0x3b, 0x76, 0xb5, 0x24, 0x42, 0x54, 0x28, 0x56, 0x3c, 0xdb, 0xca,
     0xf4, 0x75, 0x3e, 0x1b,
     0x30, 0x5a, 0xea, 0xf1, 0xab, 0xba, 0x81, 0xbb, 0x8b, 0xe4, 0x73, 0x85,
     0x64, 0xc5, 0x20, 0x2a,
     0xa1, 0xcb, 0xf4, 0xdb, 0x53, 0x9e, 0xd9, 0xc6, 0xda, 0xbe, 0x09, 0xb8,
     0xdb, 0xd5, 0x2c, 0xfe,
     0xf0, 0x3a, 0x36, 0x3a, 0xef, 0xb7, 0x10, 0x77, 0x6f, 0x74, 0x60, 0x65,
     0x46, 0xba, 0xa7, 0xab,
     0x3e, 0xa8, 0x33, 0x32, 0x7b, 0x5b, 0x26, 0x93, 0x86, 0xc4, 0xf4, 0xb5,
     0x46, 0x87, 0x90, 0x2c,
     0xe1, 0xcf, 0xf0, 0xb1, 0xa1, 0xf3, 0x23, 0xf3, 0x51, 0x88, 0x9f, 0xe7,
     0xa3, 0x42, 0xc0, 0x9d,
     0x93, 0x6f, 0xcd, 0xe4, 0x78, 0x0c, 0xc6, 0xc4, 0x4d, 0x5c, 0x40, 0x0c,
     0xac, 0xb0, 0x0b, 0xa4,
     0x36, 0xde, 0xa9, 0x8f, 0x27, 0x18, 0x64, 0x69, 0x7d, 0x3e, 0xa4, 0xa2,
     0xed, 0x0c, 0xf0, 0x09,
     0xe1, 0x38, 0x83, 0xc9, 0xe5, 0xdf, 0xf8, 0xaf, 0x37, 0xb6, 0x11, 0x0e,
     0x8a, 0xf7, 0x25, 0x58,
     0xdf, 0xa1, 0xcc, 0x36, 0xb9, 0x2e, 0xb9, 0x50, 0xe3, 0x4e, 0x88, 0xa1,
     0xca, 0xfe, 0xe3, 0x74,
     0x75, 0xcf, 0x50, 0xe8, 0xb5, 0x04, 0x27, 0xbb, 0xfc, 0x28, 0x5c, 0x92,
     0xed, 0x43, 0xce, 0x32,
     0x6f, 0xbf, 0x14, 0x41, 0xe9, 0x71, 0x85, 0xd4, 0x24, 0xb4, 0xed, 0xa5,
     0x8e, 0xa0, 0xcf, 0x75,
     0x4b, 0x8f, 0xb2, 0x48, 0x7d, 0x21, 0x51, 0x87, 0xfc, 0xd3, 0xb9, 0x6a,
     0xb0, 0xc6, 0x6e, 0x6f,
     0x31, 0xa8, 0xcb, 0xe6, 0x44, 0x53, 0xb2, 0x3a, 0xd1, 0xbb, 0xd7, 0x1c,
     0x71, 0x02, 0xce, 0xd7,
     0x53, 0xbe, 0x4f, 0xff, 0x0c, 0x35, 0xf9, 0x6c, 0xbb, 0x37, 0x6b, 0x11,
     0x15, 0xda, 0x30, 0x23,
     0x1d, 0xc7, 0x1c, 0x39, 0x7d, 0x1b, 0x49, 0x6a, 0x9f, 0xd2, 0xeb, 0xaf,
     0x03, 0xa5, 0xaf, 0x26,
     0xe2, 0x7c, 0xb6, 0x9f, 0xb0, 0x63, 0x44, 0x85, 0x1a, 0xa4, 0x4c, 0x4f,
     0xa9, 0x3a, 0xdb, 0x94,
     0x46, 0x63, 0x9a, 0x6b, 0xa0, 0xae, 0x18, 0x8f, 0x7e, 0x95, 0x0e, 0xa3,
     0x22, 0x8b, 0x98, 0xac,
     0x4a, 0xd0, 0xac, 0xcf, 0xb6, 0xca, 0x39, 0xe8, 0xb7, 0x10, 0xbe, 0xf3,
     0xa0, 0x9a, 0xc0, 0xed,
     0x17, 0xd3, 0x76, 0xa0, 0x4f, 0xc0, 0xc8, 0xb4, 0x7e, 0xde, 0xcc, 0xe7,
     0x95, 0x62, 0xfd, 0x18,
     0x5e, 0x39, 0x77, 0x9d, 0xf4, 0xe0, 0x47, 0x80, 0xd9, 0x1e, 0x11, 0xc4,
     0xe4, 0xe9, 0x5c, 0x05,
     0x33, 0x3b, 0xff, 0xf0, 0xec, 0x3e, 0x7d, 0xe2, 0x34, 0xe5, 0xe6, 0xd9,
     0x69, 0xb7, 0x2a, 0xf1,
     0x6b, 0x31, 0x0b, 0xb4, 0x6b, 0x43, 0x98, 0x58, 0x8d, 0xda, 0x7e, 0xda,
     0x6a, 0xd2, 0x53, 0x90,
     0x05, 0x76, 0x81, 0x76, 0xb8, 0xd0, 0xe7, 0xf7, 0xe2, 0xd2, 0x43, 0x5e,
     0x4f, 0x40, 0xa3, 0x12,
     0xac, 0xcd, 0x46, 0x7c, 0xd4, 0xa8, 0x6a, 0xbe, 0x95, 0x4b, 0xce, 0x56,
     0x10, 0xb5, 0x9c, 0x8b,
     0xf2, 0x99, 0xc6, 0xe1, 0x31, 0x0c, 0x22, 0x73, 0xa9, 0xef, 0xda, 0x4f,
     0xa5, 0x4e, 0x09, 0x30,
     0x46, 0x09, 0xe5, 0x2b, 0x86, 0xf0, 0x72, 0x98, 0xe9, 0x1b, 0x6a, 0x3f,
     0xdc, 0xc5, 0xa9, 0xf6,
     0xe3, 0x27, 0x53, 0x7a, 0xb0, 0xb2, 0xde, 0x67, 0xfc, 0x40, 0x2c, 0x5c,
     0x59, 0x78, 0x4b, 0x62,
     0xd6, 0xa1, 0xaa, 0xbd, 0xdf, 0xe9, 0xde, 0xd4, 0x35, 0x1f, 0xdb, 0xf7,
     0x22, 0x41, 0x6f, 0x12,
     0x1a, 0x72, 0x41, 0x38, 0x69, 0x95, 0xae, 0x4a, 0x13, 0xde, 0xd6, 0x9c,
     0xc1, 0x49, 0x6a, 0x85,
     0x50, 0xfd, 0x61, 0x00, 0xe6, 0xa4, 0xf3, 0x72, 0x5f, 0x75, 0xb0, 0x1a,
     0xd9, 0x5e, 0xeb, 0x1a,
     0x31, 0x0a, 0x7f, 0xae, 0x42, 0xaa, 0x98, 0xe1, 0x69, 0x4a, 0x9b, 0x9c,
     0xc6, 0xb7, 0x88, 0x41,
     0x8d, 0x3e, 0x35, 0xff, 0x81, 0xb1, 0x71, 0x38, 0x80, 0x71, 0x4b, 0xc7,
     0x92, 0x39, 0xa0, 0x4f,
     0x43, 0x38, 0x45, 0x26, 0x8a, 0xcf, 0x25, 0xa5, 0x14, 0x3b, 0x5f, 0x1a,
     0x14, 0xc1, 0x49, 0x44,
     0xca, 0x75, 0x80, 0x82, 0x26, 0x9b, 0x80, 0x42, 0x00, 0xf8, 0x6f, 0x78,
     0x53, 0x53, 0x7f, 0x31,
     0xd9, 0x80, 0x01, 0x01, 0xb6, 0x13, 0x65, 0x01, 0x8c, 0x53, 0xe0, 0x8c,
     0x0e, 0x6b, 0xe2, 0xa4,
     0xba, 0x34, 0xe7, 0x80, 0x8e, 0xf7, 0xaf, 0xbd, 0x98, 0xd6, 0x7e, 0x19,
     0x4c, 0x96, 0x1b, 0x70,
     0x39, 0xda, 0x90, 0x2a, 0x21, 0x28, 0x0d, 0x4e, 0x0c, 0x22, 0xee, 0xeb,
     0x5f, 0x58, 0xcc, 0xe0,
     0x37, 0x7c, 0x93, 0xe3, 0xaa, 0x6a, 0x70, 0x03, 0x24, 0x2c, 0x2f, 0xf7,
     0x3a, 0x7d, 0x35, 0x08,
     0xa1, 0xc2, 0x0b, 0x35, 0xb7, 0x73, 0xc0, 0x62, 0xe0, 0xca, 0xa1, 0x5f,
     0xf3, 0x60, 0x40, 0x4a,
     0x8b, 0xcc, 0x5e, 0xcf, 0xe7, 0x7b, 0x6e, 0xbd, 0xc4, 0x5f, 0x99, 0xe4,
     0xbb, 0x4b, 0x47, 0xe1,
     0x5e, 0xca, 0xe3, 0x46, 0x92, 0x97, 0xca, 0x7b, 0x0f, 0x42, 0x5a, 0xba,
     0xe9, 0xf8, 0x37, 0x44,
     0x8c, 0x42, 0x19, 0x6c, 0xee, 0xd2, 0x7a, 0x7e, 0x38, 0xc0, 0x0d, 0x5e,
     0xf1, 0x42, 0x92, 0xf6,
     0x51, 0xd8, 0xfb, 0xf0, 0xbb, 0x1c, 0xa6, 0xfb, 0x89, 0x82, 0xa5, 0xaf,
     0xcd, 0x0b, 0x9e, 0x96,
     0x0e, 0xdd, 0x17, 0x1a, 0xb3, 0x3f, 0xec, 0x0b, 0xa9, 0xca, 0x98, 0x65,
     0x30, 0x78, 0x02, 0x66,
     0xa8, 0x23, 0x62, 0xaf, 0xcf, 0x6d, 0xfa, 0xbf, 0xc8, 0xd6, 0x62, 0x34,
     0x74, 0xa2, 0xf3, 0x62,
     0xb9, 0x33, 0xa6, 0x10, 0xf4, 0x94, 0xb7, 0xc8, 0x7b, 0x86, 0x93, 0x3c,
     0x14, 0x6a, 0xa1, 0xd8,
     0xae, 0x4d, 0x2d, 0x4e, 0x7a, 0x12, 0x7b, 0x19, 0x4d, 0x8d, 0xe9, 0x73,
     0xa2, 0x8e, 0xfe, 0x7d,
     0x86, 0xba, 0xe6, 0x49, 0xff, 0xe0, 0xed, 0x53, 0x97, 0x80, 0x45, 0xb4,
     0x65, 0x7c, 0xd7, 0x23,
     0x00, 0x4c, 0xd0, 0x26, 0x69, 0x25, 0xab, 0xe4, 0xa3, 0x5a, 0xa2, 0x69,
     0xf4, 0xfb, 0xdc, 0x86,
     0xfb, 0xf5, 0xac, 0x58, 0x51, 0x79, 0x9a, 0xa0, 0x9f, 0x28, 0xbb, 0x6b,
     0x0d, 0xb6, 0x55, 0x5c,
     0x32, 0xde, 0x80, 0xaa, 0x67, 0x69, 0x71, 0xfa, 0x7f, 0x40, 0xd2, 0xb4,
     0xed, 0x11, 0xc6, 0xc6,
     0x38, 0x7c, 0xa1, 0x07, 0x13, 0xf3, 0x7e, 0xb3, 0xd0, 0x2e, 0x75, 0x83,
     0xfa, 0x79, 0x43, 0x3e,
     0x53, 0x61, 0x8a, 0xdf, 0x81, 0xf2, 0x48, 0x8d, 0x74, 0x5d, 0xab, 0x63,
     0x11, 0x8a, 0x52, 0xd5,
     0x62, 0x1f, 0xa1, 0xb8, 0x88, 0x0f, 0xa9, 0xae, 0xb4, 0x53, 0xc1, 0x0d,
     0xa5, 0x8b, 0xff, 0x82,
     0x3e, 0xab, 0x4d, 0xf1, 0x9e, 0xe2, 0x97, 0x02, 0xed, 0xe6, 0xeb, 0xaf,
     0x42, 0x21, 0x11, 0x3a,
     0x24, 0x8e, 0xd6, 0xee, 0xf7, 0xa0, 0xdd, 0xf6, 0x0a, 0x54, 0x20, 0x6b,
     0xa3, 0x4c, 0x3b, 0x24,
     0x1e, 0xb2, 0xff, 0x30, 0x75, 0xa4, 0x5e, 0x52, 0xc7, 0xcf, 0x8b, 0x86,
     0x83, 0x25, 0x76, 0x4f,
     0xf3, 0xb0, 0xee, 0xf0, 0xb0, 0x9c, 0x9b, 0x99, 0x88, 0x2e, 0xc4, 0xab,
     0xbd, 0xed, 0x3b, 0x69,
     0x60, 0x04, 0x3b, 0x3a, 0x1f, 0x6f, 0x36, 0x8f, 0x15, 0x16, 0xc4, 0x6d,
     0x76, 0x04, 0x81, 0x79,
     0x9f, 0x6f, 0x6c, 0xe4, 0x62, 0xc9, 0x0e, 0x6c, 0xf8, 0x09, 0x31, 0x13,
     0x8d, 0x1c, 0xff, 0xce,
     0x73, 0x87, 0x36, 0x3b, 0xee, 0x23, 0x35, 0xc2, 0x69, 0x27, 0xfe, 0x93,
     0xc1, 0x3e, 0x79, 0x50,
     0x70, 0x3e, 0xe3, 0x07, 0x99, 0x89, 0x01, 0xee, 0x77, 0xf4, 0x67, 0x62,
     0x58, 0xb6, 0x23, 0xae,
     0x12, 0x2a, 0x42, 0xee, 0x20, 0x67, 0xf7, 0xed, 0xe2, 0xd5, 0x75, 0xe6,
     0xfb, 0xd5, 0xb3, 0xbd,
     0x8e, 0xc9, 0x73, 0xc0, 0xab, 0xd0, 0x9a, 0x37, 0x95, 0xf9, 0xb9, 0x8d,
     0x0a, 0x89, 0xc0, 0xeb,
     0x48, 0xb7, 0xb0, 0xd9, 0x05, 0x57, 0x9a, 0xa5, 0x46, 0x2e, 0x87, 0xb4,
     0xcf, 0x7b, 0x00, 0xf1,
     0xef, 0xb8, 0x58, 0x53, 0x8f, 0x33, 0xf3, 0x20, 0x3c, 0xf1, 0x1b, 0x75,
     0x57, 0x06, 0xcd, 0x63,
     0xd7, 0x8f, 0xb5, 0x25, 0x3e, 0x96, 0x63, 0x72, 0xed, 0x61, 0xb2, 0x6c,
     0x07, 0xc6, 0xc6, 0x68,
     0x3e, 0xf1, 0xfb, 0xdf, 0x09, 0x82, 0x90, 0xf8, 0x02, 0xd2, 0x7c, 0xc4,
     0xc7, 0x2a, 0xd4, 0x17,
     0x44, 0x3d, 0x4f, 0xbc, 0xd2, 0x10, 0xec, 0xb6, 0x19, 0x36, 0x6a, 0x94,
     0x57, 0x74, 0x2e, 0x8e,
     0x45, 0x81, 0xd8, 0x7c, 0x5b, 0x5c, 0x58, 0x9c, 0x32, 0xe1, 0x40, 0xfb,
     0x8f, 0xf2, 0x3e, 0x56,
     0x3e, 0xcf, 0x1a, 0xb4, 0xb7, 0x74, 0x03, 0x05, 0x51, 0xf0, 0xf1, 0xca,
     0xa9, 0x82, 0x57, 0x73,
     0x08, 0x78, 0x29, 0x4b, 0x24, 0x7c, 0x9e, 0x1e, 0xe9, 0x36, 0x2d, 0x64,
     0xc4, 0x48, 0x36, 0x7c,
     0x55, 0x6a, 0xc3, 0x10, 0xa7, 0x9e, 0xc7, 0x84, 0x7b, 0x2e, 0x70, 0xfe,
     0x72, 0xfd, 0xf0, 0x82,
     0xdd, 0xc4, 0x98, 0x87, 0x23, 0x90, 0x64, 0x39, 0xf3, 0xc9, 0xcb, 0xcc,
     0x31, 0x5e, 0xb7, 0x53,
     0xee, 0x58, 0x49, 0x4d, 0x05, 0x63, 0x79, 0xa2, 0xe9, 0x84, 0xb9, 0x22,
     0x8d, 0x0a, 0x2a, 0x74,
     0x06, 0x30, 0xe3, 0x41, 0xa6, 0x90, 0x37, 0x30, 0xff, 0xfc, 0xbe, 0x24,
     0x7f, 0x62, 0xa8, 0xf5,
     0x83, 0x75, 0x45, 0x3a, 0x4d, 0xfc, 0xd1, 0x96, 0xc5, 0xe3, 0x5c, 0xde,
     0x48, 0x05, 0xbb, 0x61,
     0x57, 0x3f, 0x32, 0x86, 0x71, 0xcb, 0x4a, 0x1e, 0xa7, 0x51, 0xcb, 0x94,
     0xb0, 0x71, 0x26, 0x2f,
     0xcf, 0xe1, 0xea, 0x8b, 0x9a, 0xbe, 0xa3, 0x54, 0xfc, 0xca, 0x9e, 0xde,
     0xe5, 0x28, 0x51, 0x71,
     0xef, 0xc4, 0x2f, 0xc6, 0xf8, 0xdc, 0x7b, 0xa3, 0x54, 0xdd, 0xee, 0x0d,
     0x10, 0x5d, 0x47, 0x52,
     0xf7, 0xdb, 0xe5, 0xaf, 0x2a, 0xbf, 0xa9, 0x39, 0xf1, 0xa2, 0xc9, 0xa9,
     0x92, 0xa3, 0x4f, 0x52,
     0xa1, 0x22, 0x5b, 0x9c, 0x26, 0xe3, 0x67, 0xbd, 0x21, 0x8c, 0x52, 0x82,
     0xf3, 0x26, 0x1b, 0x72,
     0xe1, 0x68, 0x95, 0x19, 0x40, 0x43, 0x66, 0x60, 0x1b, 0x6b, 0xcb, 0xd0,
     0x05, 0xac, 0xda, 0x3e,
     0x59, 0x45, 0x4d, 0xdf, 0x91, 0x6b, 0x0c, 0xfc, 0xe8, 0x1c, 0x42, 0xc9,
     0xb2, 0x73, 0xaf, 0x51,
     0x35, 0x4d, 0x04, 0x6f, 0xb8, 0xc4, 0x50, 0x8a, 0xeb, 0x7e, 0xe8, 0xfa,
     0x68, 0xe1, 0x78, 0x35,
     0xdb, 0xe9, 0xbc, 0xdb, 0x23, 0xd3, 0x1f, 0x6a, 0x4b, 0xf0, 0x77, 0x65,
     0xf9, 0xe0, 0x99, 0x97,
     0x37, 0x3b, 0x11, 0xcc, 0xa5, 0x1f, 0x0e, 0x33, 0x48, 0x2a, 0x10, 0x92,
     0xe5, 0x8a, 0x7d, 0x62,
     0xf9, 0x81, 0xe6, 0x40, 0xf7, 0x9e, 0xbc, 0x31, 0xce, 0xf4, 0x62, 0x5c,
     0x18, 0x6b, 0x65, 0x6b,
     0x73, 0x91, 0xb6, 0x6d, 0xba, 0xb3, 0x81, 0xc3, 0xdc, 0x3a, 0xde, 0x91,
     0x60, 0x0b, 0xc2, 0xbd,
     0xd7, 0x84, 0x35, 0xac, 0xab, 0x9e, 0xfd, 0xc2, 0x75, 0x70, 0x38, 0xae,
     0x0e, 0xe6, 0x19, 0xb4,
     0x57, 0x3f, 0x25, 0x30, 0x33, 0x21, 0x70, 0x0b, 0x00, 0xa8, 0x2a, 0x0d,
     0x1c, 0xf6, 0xf2, 0x4f,
     0xc8, 0x34, 0xe6, 0x90, 0xf8, 0x29, 0x4a, 0x1f, 0x77, 0xd0, 0xfc, 0xf4,
     0x94, 0xf5, 0xa7, 0xe5,
     0x6c, 0x81, 0x1c, 0xf4, 0x43, 0x75, 0x38, 0x01, 0x9c, 0x07, 0xa4, 0xdb,
     0x63, 0x92, 0xaa, 0xa4,
     0x58, 0x81, 0x22, 0x15, 0xb1, 0x4f, 0xd8, 0x42, 0x31, 0x14, 0xb4, 0x5d,
     0x10, 0x87, 0x43, 0x8d,
     0x65, 0x05, 0x62, 0x1f, 0x9b, 0x05, 0xb9, 0xa7, 0x9d, 0xf7, 0x3c, 0xa8,
     0x62, 0x2b, 0x65, 0xe2,
     0xc6, 0x6f, 0x01, 0x6d, 0x45, 0x02, 0xcd, 0xc7, 0xbc, 0x5f, 0xca, 0x94,
     0x17, 0x89, 0xce, 0xbc,
     0x8b, 0x69, 0x13, 0x82, 0x52, 0x38, 0x23, 0xdb, 0x8e, 0x19, 0xba, 0xdc,
     0x91, 0xb4, 0xb9, 0xa0,
     0xce, 0xb1, 0xe0, 0x8c, 0xfb, 0x06, 0x4a, 0xf0, 0xb3, 0xfd, 0xd6, 0x50,
     0xe1, 0xb5, 0xe3, 0x43,
     0xc3, 0x38, 0x01, 0xbb, 0xe4, 0xce, 0x0a, 0xdf, 0x5a, 0x59, 0xdc, 0xcd,
     0xa6, 0x13, 0xdf, 0xbf,
     0xe6, 0x7b, 0x86, 0x38, 0x87, 0x62, 0x22, 0xe6, 0x0f, 0x8c, 0x2a, 0x75,
     0xfd, 0x16, 0x4d, 0xe2,
     0xdd, 0x61, 0x7a, 0x32, 0xb5, 0xab, 0x43, 0x2a, 0x0e, 0xb9, 0xbe, 0x62,
     0xfb, 0x82, 0x7b, 0x1f,
     0xbe, 0xf7, 0xbf, 0x3b, 0x1b, 0x4c, 0x3c, 0xea, 0x92, 0x9d, 0x7e, 0xe4,
     0xdd, 0xd5, 0x33, 0x57,
     0x1d, 0x75, 0xa7, 0x4b, 0x9f, 0x4d, 0x0f, 0x97, 0x86, 0x4e, 0xbf, 0x8c,
     0x5f, 0x31, 0xcb, 0x80,
     0x21, 0x5f, 0x84, 0xac, 0xe7, 0x9b, 0x7e, 0x55, 0xbb, 0xff, 0x32, 0x6c,
     0x05, 0xcc, 0x45, 0x89,
     0xea, 0xa1, 0x4b, 0x2c, 0xe8, 0xe4, 0xd5, 0x9e, 0xe3, 0x9f, 0x71, 0x35,
     0x0d, 0xa9, 0x07, 0x4b,
     0x4b, 0xc7, 0x37, 0x46, 0xaf, 0x31, 0xf5, 0x44, 0x1c, 0x8c, 0xe0, 0xfe,
     0xbe, 0x45, 0x70, 0xd8,
     0x67, 0x2f, 0x6a, 0x0c, 0xf4, 0x63, 0x4c, 0x19, 0x7b, 0xc5, 0x37, 0xa3,
     0xec, 0xde, 0x2a, 0x94,
     0xa8, 0x77, 0x56, 0xc8, 0xe4, 0x32, 0xdf, 0x5d, 0x89, 0x21, 0x03, 0xf6,
     0xe5, 0x00, 0xe8, 0xd0,
     0x91, 0x08, 0x66, 0x67, 0xeb, 0xe0, 0x62, 0x56, 0x2f, 0x7b, 0x9d, 0xd6,
     0xb9, 0x85, 0x27, 0x2b,
     0x97, 0x38, 0xd1, 0xae, 0x5f, 0xba, 0x68, 0xd6, 0xf7, 0xdb, 0x1a, 0x2a,
     0x7d, 0xcb, 0x97, 0x90,
     0x64, 0x3f, 0x33, 0xa5, 0xb2, 0x17, 0x4a, 0xc2, 0x5a, 0xbf, 0xcf, 0x4c,
     0xbf, 0xf3, 0xb5, 0x74,
     0xfa, 0x25, 0xa5, 0x37, 0x05, 0xc9, 0x1a, 0x5f, 0xe3, 0x6e, 0xee, 0x78,
     0xff, 0xc2, 0x65, 0x12,
     0x5f, 0xf6, 0xc1, 0xb5, 0xeb, 0xb2, 0x04, 0x9e, 0x04, 0xb1, 0xe2, 0x04,
     0x68, 0x22, 0xa8, 0x69,
     0xaa, 0x94, 0x0c, 0x66, 0x06, 0xde, 0x44, 0x4c, 0x51, 0x8f, 0x16, 0x03,
     0x05, 0x80, 0x2b, 0x67,
     0x9e, 0xd8, 0xfd, 0x4a, 0xe6, 0xe2, 0x27, 0xd6, 0x15, 0x72, 0x82, 0x0c,
     0x6f, 0x75, 0xad, 0x71,
     0x1d, 0x49, 0xcf, 0x0d, 0x7c, 0x91, 0x31, 0xb2, 0xd1, 0x98, 0x32, 0x7b,
     0x17, 0x24, 0xc4, 0x45,
     0x9c, 0xcb, 0xdf, 0x87, 0xb7, 0x59, 0xab, 0x72, 0xd2, 0x1a, 0xfe, 0xcc,
     0xf5, 0x36, 0x18, 0x7e,
     0xea, 0xb1, 0xa4, 0xe4, 0x23, 0x19, 0xef, 0xd7, 0xa7, 0x4d, 0x48, 0xe7,
     0x36, 0xa7, 0x77, 0xa8,
     0x28, 0x10, 0xab, 0x4d, 0xbc, 0xb8, 0xa8, 0x66, 0xc3, 0x6c, 0x93, 0xf5,
     0x7f, 0x37, 0xa8, 0x3d,
     0x67, 0x87, 0x9c, 0xfc, 0x97, 0xad, 0xb3, 0x62, 0x37, 0x3b, 0x98, 0x11,
     0x22, 0x55, 0x32, 0x16,
     0x9f, 0xc0, 0x6e, 0xfe, 0xff, 0x89, 0x7b, 0xfc, 0x04, 0x2e, 0x8b, 0x44,
     0xb0, 0xe2, 0x12, 0x91,
     0x58, 0x73, 0xd4, 0x5f, 0x6b, 0xdc, 0x18, 0xf4, 0xa1, 0x7e, 0x6b, 0xe0,
     0x7f, 0xd6, 0x15, 0xe6,
     0x67, 0xca, 0x38, 0x83, 0x1c, 0xbb, 0xe6, 0x0f, 0xf9, 0x4f, 0x05, 0x8f,
     0x9f, 0xac, 0xdf, 0xdd,
     0xc8, 0xbe, 0x82, 0x92, 0xf0, 0xdc, 0x57, 0x61, 0x05, 0xa3, 0x7a, 0xfe,
     0xf2, 0x97, 0x9f, 0x57,
     0x2f, 0xc7, 0xee, 0xde, 0xe9, 0x3c, 0xd0, 0x5b, 0x22, 0x8d, 0xbe, 0x4d,
     0x56, 0xa5, 0x1a, 0x66,
     0x92, 0x02, 0xfa, 0x19, 0x1b, 0xc1, 0xde, 0xfa, 0x2e, 0x56, 0x8d, 0x1b,
     0x3d, 0x11, 0xa8, 0x4e,
     0x06, 0x87, 0x17, 0x87, 0x76, 0x86, 0x47, 0xb1, 0xf5, 0xe4, 0x59, 0x1e,
     0x17, 0x18, 0x00, 0x0b,
     0xeb, 0x2c, 0xfa, 0xd8, 0x63, 0x51, 0x96, 0x31, 0x1f, 0x15, 0xcb, 0x2c,
     0xa2, 0xb5, 0x86, 0x24,
     0x10, 0x33, 0x23, 0x11, 0x05, 0xbf, 0x46, 0xd4, 0x8e, 0x7c, 0xde, 0xf8,
     0xa5, 0xc2, 0x3f, 0x22,
     0xcd, 0xea, 0xf5, 0xef, 0x90, 0x3f, 0x95, 0x0b, 0x1d, 0xd6, 0x18, 0xfb,
     0x78, 0xe6, 0xd2, 0x3f,
     0x72, 0xe3, 0x43, 0x55, 0x65, 0x11, 0xcf, 0x0b, 0x3b, 0x8a, 0xb4, 0x76,
     0x7e, 0x49, 0xd9, 0x99,
     0x01, 0x36, 0xab, 0xc8, 0x2a, 0x74, 0x28, 0x6c, 0x2c, 0x7d, 0xd8, 0x31,
     0xfc, 0xe5, 0xf5, 0xf9,
     0xfa, 0xec, 0x3f, 0x29, 0x72, 0xdd, 0xce, 0xd4, 0x3c, 0x11, 0x14, 0x10,
     0x96, 0xce, 0xa3, 0x26,
     0x76, 0xd9, 0x00, 0x57, 0xee, 0x41, 0x1b, 0x7e, 0x4a, 0xbf, 0x36, 0xc8,
     0x0f, 0x3a, 0xfe, 0x9c,
     0xed, 0xa3, 0x35, 0x9c, 0x3f, 0xab, 0xe7, 0xd4, 0x96, 0x04, 0xc7, 0x6c,
     0xcc, 0x0f, 0x66, 0x18,
     0xc2, 0xed, 0xeb, 0xa9, 0x63, 0x6a, 0x85, 0xec, 0x6b, 0x9a, 0xae, 0x61,
     0x64, 0xef, 0x41, 0x61,
     0x91, 0x12, 0xbc, 0x59, 0x6b, 0x46, 0x43, 0x0c, 0xf6, 0x4e, 0xb6, 0xe8,
     0xad, 0x42, 0x6d, 0x42,
     0xd8, 0x62, 0xdd, 0xfd, 0x41, 0x21, 0x00, 0xc8, 0x44, 0x10, 0xe8, 0xae,
     0x6c, 0xbf, 0xbe, 0x71,
     0x19, 0x5e, 0x5d, 0xfb, 0xa0, 0xfc, 0x4b, 0x70, 0x25, 0x63, 0x3b, 0xcc,
     0x49, 0x28, 0xd4, 0x1c,
     0x62, 0x74, 0x94, 0x14, 0x45, 0x01, 0xf3, 0x78, 0xb8, 0x13, 0x03, 0xec,
     0x5f, 0xac, 0x3f, 0xd8,
     0x8e, 0xee, 0x71, 0xe0, 0x95, 0x3f, 0x76, 0x04, 0x42, 0xcf, 0xd2, 0x56,
     0x3b, 0x5e, 0x8f, 0x28,
     0xd3, 0x0e, 0x51, 0xc1, 0xdd, 0xa9, 0x41, 0x7a, 0xa2, 0x64, 0x43, 0x9d,
     0xe3, 0x4f, 0xfa, 0x22,
     0x2c, 0xe8, 0x0e, 0x1d, 0x15, 0xbe, 0x62, 0xe3, 0xfa, 0x58, 0x1a, 0xce,
     0xd6, 0xf3, 0xe0, 0x69,
     0xdc, 0x62, 0x5e, 0x03, 0xdb, 0x57, 0xfd, 0x5e, 0xc4, 0x13, 0x43, 0x61,
     0x4b, 0x6a, 0xe9, 0x45,
     0xcf, 0xe2, 0x72, 0x9d, 0x62, 0x3a, 0x4c, 0x38, 0x4c, 0x91, 0xcc, 0xc8,
     0xd1, 0xd3, 0x7e, 0xd4,
     0xd3, 0xe7, 0x6f, 0xe2, 0xbf, 0x2d, 0x8c, 0x68, 0x4c, 0x6e, 0x62, 0x50,
     0xd6, 0x7d, 0xd5, 0x9f,
     0x12, 0x49, 0xd0, 0xe2, 0xf1, 0xd7, 0xb2, 0xd1, 0xf7, 0xb4, 0xf3, 0xc7,
     0x48, 0xcf, 0x6f, 0x97,
     0xe1, 0x97, 0x44, 0xe6, 0xb3, 0x5a, 0xc9, 0xf7, 0x71, 0x06, 0xf4, 0x2f,
     0xa6, 0xb4, 0x89, 0x33,
     0x59, 0x86, 0x74, 0x19, 0x30, 0x48, 0x04, 0x78, 0xeb, 0x53, 0x2a, 0x8d,
     0x71, 0xfe, 0xfa, 0x15,
     0x36, 0x01, 0xcf, 0x2d, 0x93, 0xe6, 0x25, 0xe9, 0xf1, 0x32, 0xa1, 0xab,
     0x4d, 0xfe, 0xaf, 0x76,
     0xac, 0x95, 0xb6, 0xf9, 0x01, 0x31, 0x7c, 0x50, 0xca, 0x32, 0x2c, 0x65,
     0x16, 0x33, 0x0b, 0x92,
     0x38, 0xdb, 0xec, 0xcb, 0x54, 0x46, 0x34, 0xd9, 0x05, 0x61, 0x9f, 0x4f,
     0x25, 0x23, 0x5d, 0x63,
     0x97, 0xb3, 0xe8, 0x0c, 0x70, 0xbd, 0xef, 0x9e, 0xde, 0x23, 0x4a, 0x1f,
     0x85, 0xe9, 0x6d, 0xd5,
     0x4a, 0xa6, 0x05, 0x3b, 0xa1, 0x06, 0x8f, 0x39, 0xdc, 0x07, 0x34, 0x62,
     0xcd, 0xe3, 0xd8, 0x60,
     0x2a, 0x3d, 0x57, 0x4f, 0x47, 0x16, 0x88, 0x74, 0x1d, 0x59, 0xd8, 0x18,
     0x1c, 0x69, 0xa7, 0xd4,
     0x15, 0xdf, 0xc3, 0xe9, 0x25, 0x04, 0x58, 0x02, 0xc5, 0x48, 0x56, 0x8a,
     0x61, 0x21, 0x89, 0xcd,
     0xf0, 0xc1, 0x82, 0xee, 0x9f, 0xe5, 0x1f, 0xed, 0x9e, 0xe1, 0xdc, 0xb4,
     0x91, 0x8f, 0xd7, 0xb9,
     0x03, 0x5a, 0xd3, 0xc7, 0x95, 0xbf, 0xa1, 0xb8, 0x64, 0x7b, 0x2b, 0xab,
     0xff, 0x29, 0xe9, 0x0a,
     0xcd, 0x9f, 0xb6, 0xc5, 0xb1, 0xa8, 0x51, 0x62, 0xc3, 0x9a, 0xce, 0xed,
     0xf3, 0xf4, 0x0b, 0x1e,
     0x02, 0xec, 0xb1, 0x4d, 0x97, 0xf9, 0x3a, 0xe0, 0x68, 0x02, 0xfc, 0x4e,
     0x22, 0x5b, 0x1d, 0x8c,
     0x12, 0x6b, 0x3b, 0x51, 0x90, 0xd6, 0x53, 0xe7, 0x80, 0x06, 0x62, 0xb0,
     0x40, 0x19, 0xf7, 0x80,
     0x8a, 0x88, 0xb0, 0x0c, 0xf2, 0x7d, 0x61, 0xf7, 0x8b, 0xea, 0x9f, 0xf2,
     0x17, 0x75, 0x92, 0x4d,
     0x16, 0x46, 0xaf, 0xca, 0xc1, 0xbc, 0xa6, 0x33, 0xc3, 0xb3, 0x7c, 0xb7,
     0xbc, 0xd3, 0x17, 0x1f,
     0x2d, 0x59, 0xa5, 0xb7, 0x15, 0xb2, 0xe8, 0xa1, 0xaa, 0x76, 0xa9, 0x8a,
     0xbe, 0x43, 0x1d, 0x6e,
     0x9d, 0xc0, 0x26, 0x82, 0x19, 0xf5, 0xfb, 0x78, 0x02, 0xfc, 0x99, 0xfa,
     0xf2, 0x52, 0x70, 0xfb,
     0x3d, 0xb5, 0xde, 0x9d, 0x71, 0x1a, 0x5c, 0x8c, 0x53, 0xea, 0xd8, 0x8c,
     0x0e, 0xb1, 0x7a, 0x7c,
     0xaa, 0xa7, 0x32, 0xf0, 0x73, 0xac, 0x08, 0x36, 0x74, 0x0b, 0x83, 0x08,
     0xdb, 0x65, 0xa4, 0xf5,
     0x92, 0x88, 0x14, 0x02, 0x5c, 0xfd, 0x89, 0xa5, 0x6e, 0x0f, 0xc6, 0x41,
     0x3f, 0xd2, 0xa5, 0xa9,
     0x1c, 0x06, 0x11, 0xe1, 0x79, 0x60, 0x79, 0xa1, 0xf5, 0x4b, 0x88, 0xb8,
     0x0c, 0x2a, 0xa0, 0xbc,
     0x44, 0x93, 0x8b, 0x4b, 0xc1, 0x97, 0x30, 0x6d, 0x15, 0x49, 0x54, 0x77,
     0x3b, 0x50, 0x85, 0xcf,
     0x3d, 0x63, 0x19, 0x6d, 0x52, 0x87, 0xe5, 0x6f, 0x6e, 0xd6, 0x81, 0x82,
     0xf3, 0x51, 0xb6, 0xef,
     0xa6, 0x48, 0x7a, 0x6e, 0x86, 0x18, 0x45, 0x97, 0x20, 0xfa, 0x27, 0xc2,
     0x6b, 0x2e, 0x47, 0xa5,
     0x66, 0x7c, 0x73, 0xa5, 0xf4, 0x25, 0x2f, 0x9c, 0x59, 0x81, 0xf6, 0x8e,
     0x70, 0x53, 0x1d, 0x9f,
     0xd0, 0xf9, 0x70, 0xbd, 0x47, 0xf0, 0xc0, 0x69, 0x32, 0xab, 0x05, 0x3b,
     0xa3, 0x4f, 0xdc, 0x4c,
     0x38, 0x06, 0xf3, 0x9c, 0x71, 0xb1, 0xb7, 0x3d, 0x77, 0x13, 0xaa, 0x27,
     0x91, 0xf9, 0x6d, 0xbe,
     0xd2, 0xa3, 0xc7, 0xf3, 0xf1, 0xa9, 0xa8, 0xf2, 0x5a, 0x8b, 0x03, 0xb7,
     0x67, 0x07, 0x7a, 0x7e,
     0xcb, 0x5a, 0xda, 0x34, 0x6a, 0x83, 0x0a, 0x8e, 0xce, 0xa4, 0x79, 0x2f,
     0xc6, 0xa4, 0x24, 0xad,
     0x62, 0x21, 0x7c, 0x2e, 0xa1, 0xb8, 0x42, 0xeb, 0x57, 0xda, 0x87, 0x75,
     0xff, 0x0d, 0xde, 0x43,
     0x45, 0x3a, 0x2d, 0x98, 0x55, 0xcd, 0x7a, 0xaf, 0xef, 0x4e, 0xf8, 0xbd,
     0x0f, 0x39, 0x2c, 0xb4,
     0x2e, 0x3d, 0xaa, 0x05, 0x1c, 0x10, 0x32, 0x55, 0x80, 0xed, 0x05, 0xe9,
     0x59, 0x94, 0x04, 0x2f,
     0xa6, 0xfc, 0x1a, 0x04, 0xf2, 0x4e, 0x8d, 0x03, 0x22, 0x55, 0x26, 0x2e,
     0x61, 0x6c, 0x92, 0x67,
     0x8c, 0x8d, 0x58, 0x4e, 0x7e, 0xbf, 0x05, 0x79, 0x9a, 0xd8, 0xdb, 0x93,
     0xe5, 0xff, 0xb4, 0x4a,
     0x8c, 0x2e, 0x7b, 0x5a, 0xfd, 0xb1, 0x69, 0x96, 0x94, 0xa2, 0x3b, 0x59,
     0x59, 0xa3, 0xeb, 0x59,
     0xad, 0x1f, 0x04, 0xcc, 0xfd, 0xe2, 0xf3, 0xb5, 0xde, 0x59, 0x2f, 0xec,
     0xc1, 0x12, 0x41, 0xbd,
     0x1a, 0xca, 0x43, 0xb5, 0xd2, 0x5d, 0xc4, 0x45, 0xc3, 0x13, 0x7c, 0xd5,
     0x26, 0x73, 0xfa, 0xb7,
     0xeb, 0x89, 0x38, 0x82, 0xb7, 0xad, 0xd0, 0x62, 0x91, 0x2b, 0xf3, 0xdd,
     0x05, 0x1f, 0xb4, 0x50,
     0x0f, 0x16, 0xc0, 0x56, 0xd6, 0xce, 0x38, 0x50, 0x6f, 0xe6, 0x0e, 0x15,
     0xff, 0x65, 0xe9, 0x92,
     0x92, 0xcf, 0xa2, 0xe9, 0x21, 0xbf, 0x69, 0xd4, 0x44, 0x9d, 0x1b, 0x50,
     0xc0, 0xe3, 0x88, 0x2c,
     0xde, 0xad, 0x83, 0xce, 0x1a, 0x21, 0xde, 0x59, 0xac, 0x9a, 0x7a, 0x70,
     0xce, 0x8d, 0xe5, 0xbb,
     0x05, 0x63, 0x84, 0xeb, 0xa0, 0x7b, 0x96, 0xa2, 0x04, 0xe5, 0xeb, 0x02,
     0x3f, 0x06, 0xa2, 0x90,
     0xc1, 0xb5, 0x4d, 0xde, 0xab, 0xf7, 0x1c, 0xe5, 0x35, 0x83, 0x65, 0x11,
     0x11, 0xd5, 0xa2, 0xc5,
     0x09, 0x9d, 0x43, 0x4b, 0x96, 0x44, 0x8a, 0x33, 0x8f, 0x42, 0x9b, 0x57,
     0x3b, 0xf5, 0xa2, 0x48,
     0xa3, 0xe1, 0xd0, 0x23, 0x5c, 0x70, 0x14, 0x94, 0xcf, 0x61, 0xfc, 0xe5,
     0xbb, 0x5b, 0x6c, 0xba,
     0x83, 0x4b, 0x5f, 0x22, 0x4c, 0xc4, 0x2c, 0xec, 0x66, 0x56, 0x0b, 0xdc,
     0xb9, 0x9f, 0x7b, 0xde,
     0xaf, 0x14, 0x88, 0x7c, 0x1b, 0xd6, 0xa5, 0x24, 0x5d, 0x92, 0x20, 0xae,
     0x01, 0xbf, 0x55, 0x88,
     0x9c, 0x08, 0x6e, 0x9c, 0x56, 0x37, 0xcd, 0x25, 0x35, 0xdd, 0xd5, 0xe4,
     0x57, 0x45, 0x89, 0x87,
     0x96, 0x8c, 0x63, 0x89, 0xb1, 0xe9, 0x8c, 0xbc, 0xe8, 0x86, 0x07, 0x26,
     0x0d, 0x61, 0xd9, 0x93,
     0x49, 0x42, 0x69, 0x94, 0x9e, 0x0d, 0x2b, 0xed, 0xfc, 0x93, 0x8b, 0xed,
     0x50, 0x7e, 0xc0, 0xd5,
     0xc5, 0xb4, 0xd3, 0x98, 0x0b, 0xc2, 0xce, 0x11, 0x7d, 0xfe, 0x0f, 0x4f,
     0xf6, 0x8a, 0x17, 0xc7,
     0x9b, 0x74, 0x67, 0x14, 0x9d, 0xae, 0x05, 0x78, 0xd8, 0xdd, 0x2b, 0xdb,
     0xfb, 0x7d, 0x53, 0x80,
     0xbe, 0x46, 0xe9, 0xb5, 0x31, 0xc3, 0xad, 0xee, 0x69, 0x2c, 0xb4, 0x44,
     0xf4, 0x2f, 0x8c, 0x4e,
     0xe8, 0x1a, 0x7e, 0xd1, 0x48, 0xca, 0x06, 0x43, 0x67, 0xd3, 0x21, 0xfb,
     0xd2, 0x5a, 0x96, 0x17,
     0xda, 0x3a, 0x7d, 0x58, 0xfd, 0x0a, 0xf7, 0x9a, 0xcf, 0x65, 0xa1, 0xe7,
     0x04, 0xef, 0xa6, 0x77,
     0xd3, 0x07, 0x73, 0x20, 0x6d, 0x1b, 0x0d, 0xbc, 0xee, 0xec, 0x56, 0x5b,
     0x9a, 0xe0, 0xdb, 0x0d,
     0x5a, 0x23, 0x4b, 0x5c, 0xcd, 0x91, 0xd0, 0xb1, 0x33, 0x49, 0xbe, 0xd5,
     0x79, 0xbe, 0x09, 0xb8,
     0x31, 0xcd, 0x0f, 0x29, 0x7d, 0x28, 0x84, 0x3b, 0x40, 0x94, 0x0c, 0x84,
     0xa0, 0x24, 0xe0, 0x56,
     0x6e, 0xf7, 0x89, 0xef, 0x34, 0x9e, 0x30, 0x98, 0xeb, 0x2c, 0x42, 0x07,
     0x7c, 0x66, 0x41, 0xdd,
     0x81, 0x57, 0xc4, 0x40, 0xfe, 0x7e, 0x03, 0xf9, 0xf5, 0x2b, 0x29, 0x49,
     0x8d, 0x6b, 0xb6, 0xad,
     0xd1, 0xfc, 0x1b, 0xf0, 0x47, 0xe6, 0x89, 0x3c, 0x00, 0x52, 0xe7, 0x6d,
     0x07, 0xcc, 0x07, 0x69,
     0xda, 0xb3, 0x29, 0x1e, 0x48, 0x58, 0xfd, 0xec, 0x1a, 0xa9, 0x43, 0xee,
     0xa8, 0xe7, 0x6b, 0x2a,
     0x88, 0x98, 0x6f, 0x5a, 0x0c, 0xcb, 0x0d, 0xe1, 0xd2, 0xd9, 0xb8, 0x28,
     0x7d, 0xb0, 0xdc, 0x80,
     0x73, 0xfe, 0x59, 0x4a, 0xee, 0x78, 0x30, 0xb1, 0x33, 0xc8, 0xcc, 0x72,
     0x2c, 0xdf, 0xae, 0xaa,
     0xac, 0xc4, 0x02, 0x99, 0xfd, 0x83, 0x51, 0xde, 0x67, 0x13, 0x4b, 0x85,
     0xbe, 0x1a, 0xd0, 0x85,
     0x03, 0x92, 0xca, 0x91, 0xee, 0xdf, 0x46, 0x4e, 0xb8, 0x2d, 0x6e, 0xb1,
     0x8e, 0xd8, 0xb5, 0x5f,
     0xb2, 0xdd, 0x7f, 0x66, 0xe6, 0x58, 0x47, 0x82, 0x42, 0x38, 0xbc, 0xda,
     0xbf, 0x54, 0x42, 0x09,
     0xa4, 0x50, 0x45, 0x51, 0xfb, 0x28, 0x5b, 0x53, 0x40, 0x47, 0xcb, 0xc9,
     0x25, 0xa1, 0x46, 0xd3,
     0x35, 0x25, 0x45, 0xda, 0xf6, 0x39, 0x3c, 0x53, 0x52, 0xbe, 0x72, 0x75,
     0xec, 0xff, 0xcd, 0x7f,
     0x93, 0xd4, 0x7f, 0x25, 0xe5, 0xf3, 0x5d, 0x8e, 0x8e, 0xcf, 0x22, 0xba,
     0xf2, 0x52, 0xaa, 0x00,
     0x09, 0xdb, 0x2f, 0x87, 0xec, 0x20, 0x75, 0xfc, 0xc8, 0xed, 0xe3, 0x4d,
     0xb5, 0xa3, 0xa5, 0x13,
     0x43, 0x59, 0x9b, 0x94, 0xdc, 0x8c, 0xa0, 0xb6, 0x2b, 0x1e, 0x71, 0xc2,
     0x1a, 0xa6, 0x29, 0x82,
     0x29, 0x47, 0x03, 0x31, 0x32, 0xad, 0xb2, 0xb4, 0xdd, 0x7e, 0xf1, 0x09,
     0xc9, 0x2e, 0xc4, 0xff,
     0x8d, 0xcb, 0x89, 0xea, 0x3f, 0x88, 0x1b, 0xbb, 0x48, 0xd1, 0x17, 0x6e,
     0xeb, 0x71, 0x30, 0x04,
     0x69, 0x13, 0x51, 0xe1, 0xce, 0x25, 0x80, 0x65, 0x85, 0xcf, 0x4d, 0xdf,
     0xe3, 0xa8, 0xb1, 0x21,
     0xa7, 0x39, 0x88, 0x1e, 0x74, 0x56, 0x3a, 0x99, 0xe1, 0x89, 0xc1, 0x34,
     0x0d, 0x72, 0xf5, 0xc6,
     0x1c, 0xf7, 0x6d, 0x55, 0xbf, 0x6c, 0x4d, 0x01, 0x94, 0xbb, 0xa0, 0x67,
     0xb3, 0xf1, 0x82, 0x1c,
     0x05, 0x3f, 0xc5, 0x49, 0xc6, 0xc7, 0xb7, 0xcc, 0x16, 0xbd, 0x00, 0x91,
     0x43, 0xa5, 0x69, 0xc6,
     0x17, 0xf7, 0x21, 0xec, 0xba, 0x40, 0xfa, 0x93, 0x7a, 0x78, 0x3a, 0xcb,
     0x29, 0x8c, 0x3b, 0x6a,
     0x49, 0x09, 0xea, 0x5b, 0x71, 0x8f, 0x9e, 0x60, 0x0c, 0xd9, 0xd0, 0x2d,
     0xa3, 0x07, 0xa6, 0xab,
     0x42, 0xcc, 0x49, 0x33, 0x8f, 0x35, 0x91, 0x18, 0x9d, 0x8e, 0x42, 0x79,
     0x7b, 0x1f, 0x36, 0x2e,
     0x41, 0xca, 0xfe, 0x22, 0x6a, 0x6a, 0xd5, 0xd0, 0xe0, 0x78, 0x19, 0x1b,
     0x60, 0x10, 0x9e, 0xe1,
     0x0a, 0x29, 0xb7, 0x3e, 0x80, 0x7d, 0x2e, 0xbe, 0x90, 0x1d, 0x73, 0x27,
     0xe3, 0x13, 0xfc, 0x43,
     0x7b, 0xb1, 0x38, 0x27, 0x79, 0xde, 0x97, 0x56, 0x5a, 0xb7, 0xb5, 0x91,
     0xd5, 0xeb, 0xfd, 0xb1,
     0x59, 0xe9, 0x26, 0x94, 0x94, 0x29, 0xab, 0x8a, 0xed, 0xfd, 0xe3, 0x4e,
     0x6a, 0x92, 0x0f, 0x92,
     0x01, 0xb4, 0x20, 0x11, 0x97, 0x20, 0x0d, 0xb5, 0x95, 0xe1, 0x05, 0x57,
     0xa8, 0x67, 0x16, 0x7d,
     0x12, 0x32, 0xbb, 0x8f, 0x64, 0x55, 0xad, 0x68, 0x75, 0xee, 0x5e, 0x86,
     0x19, 0x82, 0xee, 0xc7,
     0x72, 0xf1, 0x2f, 0x36, 0xc6, 0xd4, 0x00, 0x90, 0x95, 0xe0, 0x12, 0xd3,
     0x3e, 0x03, 0xe8, 0xbf,
     0x11, 0x63, 0xe0, 0xe8, 0xb1, 0xf3, 0xb4, 0xd5, 0x97, 0x5d, 0x92, 0xd2,
     0xe6, 0x7a, 0xb7, 0xba,
     0x9a, 0x61, 0x68, 0x69, 0x23, 0x33, 0xe2, 0xbe, 0xe6, 0x2f, 0x78, 0x7a,
     0x53, 0xe7, 0x23, 0xea,
     0x34, 0xd2, 0x2f, 0x00, 0x04, 0x5e, 0x8a, 0xa3, 0xe7, 0xab, 0xd2, 0x1c,
     0x96, 0xf6, 0xe3, 0x03,
     0xa3, 0xe9, 0xa3, 0xa0, 0x0b, 0x07, 0xf8, 0xc8, 0x71, 0x7d, 0x00, 0xba,
     0x32, 0x5b, 0x05, 0xf7,
     0xbe, 0xba, 0x2b, 0x46, 0x00, 0x9b, 0xc8, 0x87, 0xbe, 0x34, 0xa7, 0x26,
     0xdb, 0x98, 0x14, 0xac,
     0x52, 0x40, 0x19, 0x5d, 0xd6, 0xc6, 0x04, 0xca, 0x2b, 0xc9, 0xa9, 0x36,
     0xab, 0x41, 0x20, 0x9f,
     0xf8, 0x26, 0xe3, 0x63, 0x0e, 0xf4, 0xd1, 0x6c, 0xcd, 0x00, 0xf4, 0x04,
     0xf5, 0xc4, 0x34, 0xf9,
     0xa9, 0x08, 0x6f, 0x53, 0x2f, 0x46, 0x8a, 0x14, 0xb7, 0x32, 0x1b, 0x6b,
     0x36, 0xe0, 0x7d, 0xd5,
     0xf9, 0x41, 0x17, 0x4c, 0x01, 0x1c, 0xbf, 0xbc, 0xb7, 0x50, 0xb6, 0xeb,
     0x19, 0x6c, 0x26, 0xf4,
     0x68, 0xd9, 0x89, 0xe5, 0xb6, 0x7d, 0x6e, 0x98, 0x3e, 0xae, 0x2c, 0x1c,
     0x1b, 0x48, 0x31, 0xc7,
     0x07, 0xae, 0xc6, 0x28, 0x46, 0x5b, 0x32, 0x5a, 0x10, 0xe5, 0x15, 0x1e,
     0xb3, 0x49, 0xd8, 0x45,
     0x71, 0x47, 0x3b, 0x9f, 0x0a, 0x1f, 0xfc, 0xbc, 0x67, 0xa9, 0x9b, 0x19,
     0x82, 0x55, 0x81, 0x7d,
     0x38, 0x9d, 0x9d, 0x83, 0x4e, 0x5e, 0x1e, 0x58, 0x4a, 0x34, 0xf6, 0xf5,
     0x5c, 0xd5, 0x13, 0x45,
     0x71, 0xb9, 0x4f, 0x6d, 0x55, 0x4d, 0xd5, 0x83, 0xca, 0x7d, 0x1a, 0xbf,
     0x26, 0xca, 0x24, 0x08,
     0xbb, 0xbf, 0x51, 0x3d, 0x06, 0xa8, 0x11, 0x55, 0x61, 0x64, 0x77, 0x32,
     0x4b, 0x12, 0xd0, 0xbf,
     0x38, 0xb1, 0xb0, 0x25, 0x73, 0x75, 0x5e, 0xa8, 0x7f, 0x9e, 0x14, 0x1f,
     0x04, 0x1c, 0x1b, 0xd4,
     0x77, 0x2d, 0x3e, 0x61, 0x7e, 0x57, 0x13, 0x33, 0xc2, 0xcc, 0x4f, 0x65,
     0x45, 0xc5, 0x03, 0x17,
     0xf3, 0x46, 0x45, 0xb8, 0xd6, 0xac, 0xed, 0x10, 0xbb, 0x9d, 0xd4, 0x9a,
     0x68, 0x46, 0x73, 0xb1,
     0xea, 0x84, 0x11, 0xaa, 0x34, 0xa5, 0x4f, 0x04, 0xdb, 0x88, 0x21, 0x4d,
     0x09, 0xd1, 0x25, 0x44,
     0xc4, 0xf9, 0x75, 0xb4, 0xfd, 0xd4, 0x10, 0x4e, 0x80, 0xa4, 0x62, 0xff,
     0x14, 0x1b, 0x8a, 0x8a,
     0x20, 0x2a, 0x26, 0xe6, 0x31, 0x70, 0x1e, 0x59, 0xa5, 0xb7, 0x1d, 0x3b,
     0x04, 0x40, 0x00, 0xba,
     0x80, 0xf6, 0xbd, 0x64, 0x0d, 0x7b, 0x33, 0x61, 0xe4, 0x08, 0x68, 0x27,
     0xed, 0x4b, 0xd3, 0x1d,
     0x7b, 0xee, 0x02, 0x3a, 0x8c, 0x89, 0xdb, 0xba, 0x16, 0xec, 0xf3, 0x78,
     0x72, 0x33, 0xcf, 0x05,
     0xa2, 0xf8, 0xc4, 0x77, 0x05, 0xae, 0x18, 0xa3, 0x8d, 0x24, 0x28, 0xa4,
     0xfe, 0x72, 0x31, 0x42,
     0x44, 0xa6, 0x12, 0xc8, 0x4a, 0xea, 0x82, 0x02, 0x90, 0x55, 0x44, 0xef,
     0x6e, 0x7e, 0x13, 0x77,
     0x1f, 0xec, 0xdd, 0xe4, 0x5f, 0xe7, 0x77, 0xb7, 0x59, 0x91, 0x76, 0x58,
     0x84, 0x1d, 0xe1, 0x5b,
     0x76, 0x6d, 0xf2, 0x3f, 0x5e, 0x42, 0xd3, 0xe9, 0x9a, 0xf9, 0xfe, 0xef,
     0x76, 0x62, 0xff, 0xcf,
     0xa3, 0x54, 0x90, 0x46, 0xb5, 0x14, 0xa4, 0xf6, 0xcd, 0x2d, 0x48, 0x6f,
     0xf2, 0x9d, 0x07, 0x95,
     0x03, 0xb5, 0xa6, 0xf7, 0x86, 0x92, 0x30, 0x72, 0x0e, 0x4f, 0x7f, 0x15,
     0x2c, 0xe3, 0x5a, 0xb1,
     0x62, 0x60, 0xb2, 0x54, 0x51, 0x0b, 0x76, 0x25, 0xd6, 0xd3, 0x6b, 0xd6,
     0x8c, 0x76, 0x8d, 0x51,
     0x77, 0x37, 0x23, 0xd7, 0x13, 0xdd, 0x7b, 0xf8, 0xe3, 0xf8, 0x87, 0x57,
     0x74, 0x02, 0x40, 0xd3,
     0x19, 0x54, 0x0c, 0xa8, 0x7f, 0x49, 0x75, 0x6f, 0xd5, 0xa9, 0x3a, 0x12,
     0xd6, 0xd8, 0x94, 0xee,
     0x80, 0x9c, 0x80, 0xc1, 0xd9, 0x82, 0x2b, 0x17, 0x7c, 0x1b, 0x14, 0x7a,
     0x31, 0x88, 0xc0, 0xe5,
     0xd6, 0xaf, 0xfe, 0xa8, 0x11, 0x11, 0x5f, 0xc2, 0x3c, 0x1d, 0x05, 0x99,
     0x1e, 0x80, 0xf8, 0x14,
     0xed, 0xec, 0xaa, 0xe0, 0x75, 0x88, 0x09, 0x1c, 0x28, 0x6d, 0xa4, 0x52,
     0x04, 0x35, 0x37, 0xc1,
     0xcf, 0x78, 0xd7, 0x40, 0x54,};

uint8_t msg_mt_40_2[] =
    {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x66,
     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62,
     0x63, 0x64, 0x65, 0x0a,};

const test_vector mt_vector_40_2 = {
    .name = "xmss_mt_ref_40_2",
    .key = pk_mt_40_2,
    .keyLen = sizeof(pk_mt_40_2),
    .sig = sig_mt_40_2,
    .sigLen = sizeof(sig_mt_40_2),
    .msg = msg_mt_40_2,
    .msgLen = sizeof(msg_mt_40_2)};
#ifdef __cplusplus
}
#endif

#endif /* _QUARK_XMSSMT_REF_VEC_H_ */
