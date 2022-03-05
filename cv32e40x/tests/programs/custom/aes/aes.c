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
** AES Encryption and decryption test: Creates roundkeys, encrypts and decrypts
**                                     a message using ZKNE and ZKND 
**                                     instructions.
**                                     
**
*******************************************************************************
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROTATE_32_RIGHT(value) ((value&0x00FFFFFF) << 8) | ((value&0xFF000000) >> 24)

void print_msg_hex(char* msg, uint16_t msg_length)
{
    printf("Msg       = ");
    for(uint16_t i = 0; i < msg_length; i++){
        if(i % 4 == 0 && i > 0) printf(" ");
        printf("%x", msg[i]);
    }
    printf("\n");    
    
}
void print_cipher(uint32_t* cipher, uint32_t msg_length)
{
    const uint8_t number_of_blocks = msg_length >= 128 ? msg_length/128 : 1;
    for(uint8_t block = 0; block < number_of_blocks; block++)
    {
        printf("Encrypted Block %02i: ", block);
        for(uint8_t word = 0; word < 4; word++)
            printf("%08lx ", cipher[block*4 + word]);
        printf("\n");    
    }   
}
void print_roundkeys(uint32_t* key, uint16_t key_length)
{
    const uint8_t number_of_keys = (key_length == 128) ? 11 : (key_length == 192) ? 13 : 15;
    for(uint8_t round = 0; round < number_of_keys; round++)
    {
        printf("RoundKey %02i: ", round);
        for(uint8_t word = 0; word < 4; word++)
            printf("%08lx ", key[round*4 + word]);
        printf("\n");    
    }    
}

uint32_t* key_scheduler(const uint32_t* key, const uint16_t key_length)
{
    volatile uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;
    volatile uint8_t N = key_length/32;
    volatile uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    volatile uint32_t* round_keys = malloc(128/32 * (rounds + 1) * sizeof *round_keys);

    for(uint8_t i = 0; i <  4 * rounds + 4; i++)
    {
        if(i < N)
            round_keys[i] = key[i];
        else if(i >= N && i%N == 0)
        {
            round_keys[i] = 0;
            volatile uint32_t tmp_key_i = ROTATE_32_RIGHT(round_keys[i - 1]);
            __asm__ volatile("aes32esi %0, %1, %2, 0":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            __asm__ volatile("aes32esi %0, %1, %2, 1":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            __asm__ volatile("aes32esi %0, %1, %2, 2":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            __asm__ volatile("aes32esi %0, %1, %2, 3":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            round_keys[i] = round_keys[i] ^ (rcon[i/N - 1] << 24); //RCON[0] ??
            round_keys[i] = round_keys[i] ^ round_keys[i - N];
        }
        else if(i >= N && N > 6 && i % N == 4)
        {
            round_keys[i] = 0;
            __asm__ volatile("aes32esi %0, %1, %2, 0":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            __asm__ volatile("aes32esi %0, %1, %2, 1":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            __asm__ volatile("aes32esi %0, %1, %2, 2":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            __asm__ volatile("aes32esi %0, %1, %2, 3":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            round_keys[i] = round_keys[i] ^ round_keys[i - N];
        }
        else
            round_keys[i] = round_keys[i - 1] ^ round_keys[i - N];
    }

    return round_keys;
}

uint32_t* encrypt(char* msg, uint16_t msg_length, uint32_t* round_keys, uint16_t key_length)
{
    const uint16_t padded_length = msg_length/128 * 128 + 128;
    uint32_t* padded_msg = malloc(padded_length);
    
    //uint8_t[] -> uint32_t[] creates problems with endianess.. 
    //This is not an efficient procedure, but it works.. 
    //An idea could be to fix the round keys to match
    //the endianess of the input text
    memset(padded_msg, 0, padded_length); 
    // memcpy(padded_msg, msg, msg_length);
    for(uint32_t i = 0; i < msg_length; i++)
        (padded_msg)[i/4] |= ((uint32_t)msg[i]) << (3-i%4)*8; 

    print_cipher(padded_msg, padded_length); 

    const uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;


    uint32_t* cipher = malloc(padded_length);
    for(uint8_t msg_block = 0; msg_block < padded_length/128; msg_block++){
        //AddRoundKey
        cipher[msg_block*4 + 0] = padded_msg[msg_block*4 + 0] ^ round_keys[0]; 
        cipher[msg_block*4 + 1] = padded_msg[msg_block*4 + 1] ^ round_keys[1];
        cipher[msg_block*4 + 2] = padded_msg[msg_block*4 + 2] ^ round_keys[2];
        cipher[msg_block*4 + 3] = padded_msg[msg_block*4 + 3] ^ round_keys[3];
        print_cipher(cipher, msg_length);

        // 10/12/14 rounds with MixColumn
        for(uint8_t i = 1; i < rounds; i++){
            uint32_t key_tmp[4]    = {round_keys[i*4], round_keys[i*4+1], round_keys[i*4+2], round_keys[i*4+3]};
            uint32_t cipher_tmp[4] = {cipher[msg_block*4 + 0], cipher[msg_block*4 + 1], cipher[msg_block*4 + 2], cipher[msg_block*4 + 3]};
            for(uint8_t i = 0; i < 4; i++){
                printf("key[%i] = %08lx \n", i,key_tmp[i]);
            }
            for(uint8_t i = 0; i < 4; i++){
                printf("cipher[%i] = %08lx \n",i,  cipher[i]);
            }
            // printf("Input kt: %lx ", key_tmp[0]);
            __asm__ volatile("aes32esmi %0, %1, %2, 3": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[0]));
            __asm__ volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[1]));
            __asm__ volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[2]));
            __asm__ volatile("aes32esmi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 0]): "0"(key_tmp[0]), "r"(cipher_tmp[3]));

            __asm__ volatile("aes32esmi %0, %1, %2, 3": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[1]));
            __asm__ volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[2]));
            __asm__ volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[3]));
            __asm__ volatile("aes32esmi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 1]): "0"(key_tmp[1]), "r"(cipher_tmp[0]));

            __asm__ volatile("aes32esmi %0, %1, %2, 3": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[2]));
            __asm__ volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[3]));
            __asm__ volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[0]));
            __asm__ volatile("aes32esmi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 2]): "0"(key_tmp[2]), "r"(cipher_tmp[1]));

            __asm__ volatile("aes32esmi %0, %1, %2, 3": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[3]));
            __asm__ volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[0]));
            __asm__ volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[1]));
            __asm__ volatile("aes32esmi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 3]): "0"(key_tmp[3]), "r"(cipher_tmp[2]));
            print_cipher(cipher, msg_length);
        }
        // Last round does not require MixColumn

        uint32_t key_tmp[4]    = {round_keys[rounds-1], round_keys[rounds-1], round_keys[rounds-1], round_keys[rounds-1]};
        uint32_t cipher_tmp[4] = {cipher[msg_block*4 - 4], cipher[msg_block*4 - 3], cipher[msg_block*4 - 2], cipher[msg_block*4 - 1]};
        __asm__ volatile("aes32esi %0, %1, %2, 3": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[0]));
        __asm__ volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[1]));
        __asm__ volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[2]));
        __asm__ volatile("aes32esi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 0]): "0"(key_tmp[0]), "r"(cipher_tmp[3]));

        __asm__ volatile("aes32esi %0, %1, %2, 3": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[1]));
        __asm__ volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[2]));
        __asm__ volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[3]));
        __asm__ volatile("aes32esi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 1]): "0"(key_tmp[1]), "r"(cipher_tmp[0]));

        __asm__ volatile("aes32esi %0, %1, %2, 3": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[2]));
        __asm__ volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[3]));
        __asm__ volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[0]));
        __asm__ volatile("aes32esi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 2]): "0"(key_tmp[2]), "r"(cipher_tmp[1]));

        __asm__ volatile("aes32esi %0, %1, %2, 3": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[3]));
        __asm__ volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[0]));
        __asm__ volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[1]));
        __asm__ volatile("aes32esi %0, %1, %2, 0": "=r"(cipher[msg_block*4 + 3]): "0"(key_tmp[3]), "r"(cipher_tmp[2]));
    }
    printf("Cipher end = %lx\n", cipher[0]);
    return cipher;
}


int main(int argc, char *argv[])
{
    uint16_t key_length = 128;
    uint32_t* aes_key = malloc(8*sizeof *aes_key);
    aes_key[0] = 0x54686174;
    aes_key[1] = 0x73206D79;
    aes_key[2] = 0x204B756E;
    aes_key[3] = 0x67204675;
    // // aes_key[4] = 
    // // aes_key[5] = 
    // // aes_key[6] = 
    // // aes_key[7] = 

    volatile uint32_t* round_keys;
    round_keys = key_scheduler(aes_key, key_length);
    print_roundkeys(round_keys, key_length);
    
    
    char msg[] = {'T','w','o',' ','O', 'n', 'e', ' ', 'N', 'i', 'n','e',' ','T','w','o'};
    uint16_t msg_length = sizeof(msg)/sizeof(char);
    uint32_t* cipher = encrypt(msg, msg_length, round_keys, key_length);
    print_msg_hex(msg, msg_length);
    print_cipher(cipher, msg_length);
    // // char* decipher   = decrypt(); 






    /* inline assembly */
    // aes32esmi rd rs1 rs2 bs, One of rs are usually the same as rd, bs=byteselect
    // __asm__ volatile("aes32esi %1, %2, %0, 0": "=r"((result[0]) : "r"((aes_i), "r"((key_i));
    // __asm__ volatile("aes32dsi %1, %2, %0, 1": "=r"((result[1]) : "r"((aes_i), "r"((key_i));
    // __asm__ volatile("aes32esi %1, %2, %0, 2": "=r"((result[2]) : "r"((aes_i), "r"((key_i));
    // __asm__ volatile("aes32esi %1, %2, %0, 3": "=r"((result[3]) : "r"((aes_i), "r"((key_i));
    // __asm__ volatile("aes32esmi %1, %2, %0, 2": "=r"((result[2]) : "r"((aes_i), "r"((key_i));
    // __asm__ volatile("aes32dsmi %1, %2, %0, 3": "=r"((result[3]) : "r"((aes_i), "r"((key_i));


    /* Print a banner to stdout and interpret MISA CSR */
    // printf("\nAdvanced Encryption Standard \n");
    // for(uint i = 0; i < 4; i++)
    //     printf("RUN%i: AES input = %x \nAES key = %x\nResult = %x\n\n", i, aes_i, key_i, result[i]);

}
