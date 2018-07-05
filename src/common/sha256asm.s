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
 *  Description : Accelerated ASM-based SHA256 compression function.
 */
    .section sha_code
    .text
    .syntax unified
    .align    0


/*******************************************************************************/
/** quark_sha256_asm_compress( *pwState, *pDataBlock )                          **/
/**                                                                           **/
/**   Updates pwState state based on hashing block stored in pDataBlock[].    **/
/**                                                                           **/
/**   r0 points to pwState                                                    **/
/**   r1 will hold a, used as pointer to pDataBlock[i] initially              **/
/**   r2 will hold b                                                          **/
/**   r3 will hold c                                                          **/
/**   r4 will hold d                                                          **/
/**   r5 will hold e                                                          **/
/**   r6 will hold f                                                          **/
/**   r7 will hold g                                                          **/
/**   r8 will hold h                                                          **/
/**   r9 used as loop counter                                                 **/
/**   r10 will point to Wt[i], and be used as temp                            **/
/**   r11 used as temp                                                        **/
/**   r12 used as temp                                                        **/
/**                                                                           **/
/*******************************************************************************/
    .global  quark_sha256_asm_compress
    .func    quark_sha256_asm_compress
quark_sha256_asm_compress:
    STMFD    SP!, {r2-r12}           /* save the required registers                                                */
    LDR      r10, =wt_asm            /* r10 = *Wt[0]                                                               */
    MOV      r9, #16                 /* i = 16                                                                     */
sha256xform_decode:
    /* Perform endian-swap on pDataBlock[] and write to Wt[ ] array                                                */
    LDR      r2, [r1], #4            /* r2 = pDataBlock[i] = 0x12345678, r1 = *pDataBlock[i+1]                     */
    REV      r3, r2                  /* r3 = BYTE_REVERSAL(r2)                                                     */
    STR      r3, [r10], #4           /* Wt[i] = 0x78563412, r10 = *Wt[i+1]                                         */
    SUBS     r9, r9, #1              /* i--                                                                        */
    BNE      sha256xform_decode      /* repeat if (i != 0)                                                         */
    MOV      r9, #16                 /* i = 16                                                                     */
    LDR      r10, =wt_asm            /* reset r10 = *Wt[0]                                                         */
sha256xform_init_wt:
    /* Expand pDataBlock[] into Wt[ ] array                                                                        */
    SUB      r1, r9, #2              /* r1 = (i-2)                                                                 */
    LDR      r1, [r10, r1, LSL #2]   /* r1 = Wt[i-2]                                                               */
    MOV      r2, r1, ROR #17         /* r2 = ROR(Wt[i-2],17)                                                       */
    EOR      r2, r2, r1, ROR #19     /* r2 = ROR(Wt[i-2],17) ^ ROR(Wt[i-2],19)                                     */
    EOR      r2, r2, r1, LSR #10     /* r2 = LSIG1(Wt[i-2]) = ROR(Wt[i-2],17) ^ ROR(Wt[i-2],19) ^ (Wt[i-2] >> 10)  */
    SUB      r1, r9, #7              /* r1 = (i-7)                                                                 */
    LDR      r1, [r10, r1, LSL #2]   /* r1 = Wt[i-7]                                                               */
    ADD      r2, r2, r1              /* r2 = LSIG1(Wt[i-2]) + Wt[i-7]                                              */
    SUB      r1, r9, #15             /* r1 = (i-15)                                                                */
    LDR      r1, [r10, r1, LSL #2]   /* r1 = Wt[i-15]                                                              */
    MOV      r3, r1, ROR #7          /* r3 = ROR(Wt[i-15],7)                                                       */
    EOR      r3, r3, r1, ROR #18     /* r3 = ROR(Wt[i-15],7) ^ ROR(Wt[i-15],18)                                    */
    EOR      r3, r3, r1, LSR #3      /* r3 = LSIG0(Wt[i-15]) = ROR(Wt[i-15],7) ^ ROR(Wt[i-15],18) ^ (Wt[i-15]>>3)  */
    ADD      r2, r2, r3              /* r2 = LSIG1(Wt[i-2]) + Wt[i-7] + LSIG0(Wt[i-15])                            */
    SUB      r1, r9, #16             /* r1 = (i-16)                                                                */
    LDR      r3, [r10, r1, LSL #2]   /* r3 = Wt[i-16]                                                              */
    ADD      r2, r2, r3              /* r2 = LSIG1(Wt[i-2]) + Wt[i-7] + LSIG0(Wt[i-15]) + Wt[i-16]                 */
    STR      r2, [r10, r9, LSL #2]   /* Wt[i] = LSIG1(Wt[i-2]) + Wt[i-7] + LSIG0(Wt[i-15]) + Wt[i-16]              */
    ADD      r9, r9, #1              /* i++                                                                        */
    CMP      r9, #64                 /* repeat if (i < 64)                                                         */
    BLT      sha256xform_init_wt     /*                                                                            */
sha256xform_state:
    /* Load pwState[] = {a, b, c, d, e, f, g, h} into {r1, r2, r3, r4, r5, r6, r7, r8}                             */
    LDMIA    r0, {r1-r8}             /* {r1-r8} = {a - h}                                                          */
     MOV     r9, #0                  /* i = 0                                                                      */
sha256xform_round:
    /* Compute T1 = h + BSIG1(e) + Ch(e, f, g) + Kt[i] + Wt[i]                                                     */
    MOV      r10, r5, ROR #6         /* r10 = ROR(e, 6)                                                            */
    EOR      r10, r10, r5, ROR #11   /* r10 = ROR(e, 6) ^ ROR(e, 11)                                               */
    EOR      r10, r10, r5, ROR #25   /* r10 = BSIG1(e) = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)                       */
    AND      r11, r5,  r6            /* r11 = e&f                                                                  */
    MVN      r12, r5                 /* r12 = ~e                                                                   */
    AND      r12, r12, r7            /* r12 = ~e&g                                                                 */
    EOR      r12, r12, r11           /* r12 = Ch(e,f,g) = (e&f) ^ (~e&g)                                           */
    ADD      r10, r10, r12           /* r10 = BSIG1(e) + Ch(e,f,g)                                                 */
    ADD      r10, r10, r8            /* r10 = h + BSIG1(e) + Ch(e,f,g)                                             */
    LDR      r11, =kt_256            /* r11 = *Kt[0]                                                               */
    LDR      r11, [r11, r9, LSL #2]  /* r11 = Kt[i]                                                                */
    ADD      r10, r10, r11           /* r12 = h + BSIG1(e) + Ch(e,f,g) + K[i]                                      */
    LDR      r11, =wt_asm            /* r11 = *Wt[0]                                                               */
    LDR      r11, [r11, r9, LSL #2]  /* r11 = Wt[i]                                                                */
    ADD      r12, r10, r11           /* r12 = T1 = h + BSIG1(e) + Ch(e,f,g) + Kt[i] + Wt[i]                        */
    MOV      r8,  r7                 /* h = g                                                                      */
    MOV      r7,  r6                 /* g = f                                                                      */
    MOV      r6,  r5                 /* f = e                                                                      */
    ADD      r5,  r4,  r12           /* e = d + T1                                                                 */
    MOV      r4,  r3                 /* d = c                                                                      */
    MOV      r3,  r2                 /* c = b                                                                      */
    MOV      r2,  r1                 /* b = a, r1 now available for temp vars                                      */
    MOV      r10, r2, ROR #2         /* r10 = ROR(a,2)                                                             */
    MOV      r11, r2, ROR #13        /* r11 = ROR(a,13)                                                            */
    EOR      r10, r10, r11           /* r10 = ROR(a,2) ^ ROR(a,13)                                                 */
    MOV      r11, r2, ROR #22        /* r11 = ROR(a,13)                                                            */
    EOR      r10, r10, r11           /* r10 = BSIG0(a) = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22)                          */
    ADD      r10, r10, r12           /* r10 = T1 + BSIG0(a), r12 available                                         */
    AND      r11, r2,  r3            /* r11 = a&b                                                                  */
    AND      r12, r2,  r4            /* r12 = a&c                                                                  */
    EOR      r11, r11, r12           /* r11 = (a&b) ^ (a&c)                                                        */
    AND      r12, r3,  r4            /* r12 = b&c                                                                  */
    EOR      r11, r11, r12           /* r11 = (a&b) ^ (a&c) ^ (b&c)                                                */
    ADD      r1,  r10, r11           /* a = r1 = T1 + T2                                                           */
    ADD      r9,  r9,  #1            /* i++                                                                        */
    CMP      r9,  #64                /*                                                                            */
    BLT      sha256xform_round       /* repeat if (i < 64)                                                         */
sha256xform_update:
    /* Update pwState[]                                                                                            */
    LDR      r9, [r0]                /* r9 = state[0]                                                              */
    ADD      r9, r9, r1              /* r9 = state[0] + a                                                          */
    STR      r9, [r0], #4            /* state[0] = state[0] + a, r0 = *state[1]                                    */
    LDR      r9, [r0]                /* r9 = state[1]                                                              */
    ADD      r9, r9, r2              /* r9 = state[1] + b                                                          */
    STR      r9, [r0], #4            /* state[1] = state[1] + b, r0 = *state[2]                                    */
    LDR      r9, [r0]                /* r9 = state[2]                                                              */
    ADD      r9, r9, r3              /* r9 = state[2] + c                                                          */
    STR      r9, [r0], #4            /* state[2] = state[2] + c, r0 = *state[3]                                    */
    LDR      r9, [r0]                /* r9 = state[3]                                                              */
    ADD      r9, r9, r4              /* r9 = state[3] + d                                                          */
    STR      r9, [r0], #4            /* state[3] = state[3] + d, r0 = *state[4]                                    */
    LDR      r9, [r0]                /* r9 = state[4]                                                              */
    ADD      r9, r9, r5              /* r9 = state[4] + e                                                          */
    STR      r9, [r0], #4            /* state[4] = state[4] + e, r0 = *state[5]                                    */
    LDR      r9, [r0]                /* r9 = state[5]                                                              */
    ADD      r9, r9, r6              /* r9 = state[5] + f                                                          */
    STR      r9, [r0], #4            /* state[5] = state[5] + f, r0 = *state[6]                                    */
    LDR      r9, [r0]                /* r9 = state[6]                                                              */
    ADD      r9, r9, r7              /* r9 = state[6] + g                                                          */
    STR      r9, [r0], #4            /* state[6] = state[6] + g, r0 = *state[7]                                    */
    LDR      r9, [r0]                /* r9 = state[7]                                                              */
    ADD      r9, r9, r8              /* r9 = state[7] + h                                                          */
    STR      r9, [r0]                /* state[7] = state[7] + h                                                    */
sha256xform_done:
    LDMFD    SP!, {r2-r12}           /* restore the required registers                                             */
    MOV      PC, LR                  /* return to calling program                                                  */
    .endfunc

/*******************************************************************************/
/** Define data region to hold constants used during functions                **/
/*******************************************************************************/
    .section sha_data
    .data
    .align    0
    /* Reserve 256 bytes for storing Wt[ ] array (SHA-256: 64 * 4B = 256B)                                         */
wt_asm:    .skip    256

    /* Define Kt[ ] array for SHA-256                                                                              */
kt_256:
    .word    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

    .end
