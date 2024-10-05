#include<stdio.h>
#include<string.h>
#include"utilityAES128.h"

int main() {
    unsigned char key[Nk][4] = {
        {0x2b, 0x7e, 0x15, 0x16},
        {0x28, 0xae, 0xd2, 0xa6},
        {0xab, 0xf7, 0x15, 0x88},
        {0x09, 0xcf, 0x4f, 0x3c}
    };
    unsigned char input[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    unsigned char output[16];
    unsigned char w[Nb * (Nr + 1)][4];

    KeySchedule(key, w);

    AES_Encrypt(input, output, w);

    printf("Encrypted message: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");

    unsigned char decrypted_output[16];
    AES_Decrypt(output, decrypted_output, w);

    printf("Decrypted message: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted_output[i]);
    }
    printf("\n");

    return 0;
}