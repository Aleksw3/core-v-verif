/*
**
** Copyright 2020 OpenHW Group
**
** Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     https://solderpad.org/licenses/
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
**
*******************************************************************************
**
** Sanity test for the CV32E40X core.  Reads the MVENDORID, MISA, MARCHID and
**                                     MIMPID CSRs and prints some useful (?)
**                                     messages to stdout.  Will fail if these
**                                     CSRs do not match expected values.
**
*******************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>

#define EXP_MISA 0x40001104

int main(int argc, char *argv[])
{
    volatile unsigned int aes_i  = 10;
    volatile unsigned int key_i  = 20;
    volatile unsigned int result[4] = {0};


    /* inline assembly */
    // aes32esmi rs1 rs2 rd bs, One of rs are usually the same as rd, bs=byteselect
    __asm__ volatile("aes32esi %1, %2, %0, 0": "=r"(result[0]) : "r"(aes_i), "r"(key_i));
    __asm__ volatile("aes32dsi %1, %2, %0, 1": "=r"(result[1]) : "r"(aes_i), "r"(key_i));
    __asm__ volatile("aes32esi %1, %2, %0, 2": "=r"(result[2]) : "r"(aes_i), "r"(key_i));
    __asm__ volatile("aes32esi %1, %2, %0, 3": "=r"(result[3]) : "r"(aes_i), "r"(key_i));
    // __asm__ volatile("aes32esmi %1, %2, %0, 2": "=r"(result[2]) : "r"(aes_i), "r"(key_i));
    // __asm__ volatile("aes32dsmi %1, %2, %0, 3": "=r"(result[3]) : "r"(aes_i), "r"(key_i));


    /* Print a banner to stdout and interpret MISA CSR */
    printf("\nAdvanced Encryption Standard \n");
    for(uint i = 0; i < 4; i++)
        printf("RUN%i: AES input = %x \nAES key = %x\nResult = %x\n\n", i, aes_i, key_i, result[i]);

}
