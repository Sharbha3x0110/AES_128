#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include "utility_ECB.h"

int main() {
    unsigned char key[Nk][4] = {
        {0x2b, 0x7e, 0x15, 0x16},
        {0x28, 0xae, 0xd2, 0xa6},
        {0xab, 0xf7, 0x15, 0x88},
        {0x09, 0xcf, 0x4f, 0x3c}
    };
    
    unsigned char w[Nb * (Nr + 1)][4];

    KeySchedule(key,w);

    AES_ECB_encrypt_file("input.txt", "encrypted.txt", w);
    AES_ECB_decrypt_file("encrypted.txt", "decrypted.txt", w);

    return 0;
}