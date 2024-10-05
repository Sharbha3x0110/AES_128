#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "utility_CBC.h"

int main() {
    unsigned char key[Nk][4] = {
        {0x2b, 0x7e, 0x15, 0x16},
        {0x28, 0xae, 0xd2, 0xa6},
        {0xab, 0xf7, 0x15, 0x88},
        {0x09, 0xcf, 0x4f, 0x3c}
    };
    unsigned char iv[16] = {
        0x12, 0x34, 0x56, 0x78, 
        0x9a, 0xbc, 0xde, 0xf0, 
        0x11, 0x22, 0x33, 0x44, 
        0x55, 0x66, 0x77, 0x88
      };
    unsigned char w[Nb * (Nr + 1)][4];

    KeySchedule(key,w);

    AES_CBC_encrypt_file("input.txt", "encrypted.txt", w, iv);
    AES_CBC_decrypt_file("encrypted.txt", "decrypted.txt", w, iv);

    return 0;
}