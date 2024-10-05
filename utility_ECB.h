#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utilityAES128.h" 





// Apply PKCS#7 padding
void pad_buffer(unsigned char* buffer, int len, int block_size) {
    int pad_value = block_size - len;
    for (int i = len; i < block_size; i++) {
        buffer[i] = (unsigned char)pad_value;
    }
}

// Remove PKCS#7 padding
void unpad_buffer(unsigned char* buffer, int* len) {
    int pad_value = buffer[*len - 1];
    *len -= pad_value;
}

// Encrypt a file using AES-128 in ECB mode
void AES_ECB_encrypt_file(const char* input_filename, const char* output_filename, unsigned char w[Nb * (Nr + 1)][4]) {
    FILE* input_file = fopen(input_filename, "rb");
    FILE* output_file = fopen(output_filename, "wb");

    if (!input_file || !output_file) {
        perror("File open failed");
        return;
    }

    unsigned char buffer[16];
    unsigned char ciphertext[16];
    

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, 16, input_file)) == 16) {
        
        AES_Encrypt(buffer, ciphertext, w);
        fwrite(ciphertext, 1, 16, output_file);
       
    }

    // Handle padding for the last block
    while (bytes_read > 0 && bytes_read != 16) {
        int n = bytes_read % 16;
        pad_buffer(buffer, n, 16);
        
        AES_Encrypt(buffer, ciphertext, w);
        fwrite(ciphertext, 1, 16, output_file);
        bytes_read = 16;
    }

    while (bytes_read == 0) {
        
        memset(buffer, 16, 16); // Block filled with value 0x10
        
        AES_Encrypt(buffer, ciphertext, w);
        fwrite(ciphertext, 1, 16, output_file);
        bytes_read = 1;
    }

    fclose(input_file);
    fclose(output_file);
}

// Decrypt a file using AES-128 in ECB mode
void AES_ECB_decrypt_file(const char* input_filename, const char* output_filename, unsigned char w[Nb * (Nr + 1)][4]) {
    FILE* input_file = fopen(input_filename, "rb");
    FILE* output_file = fopen(output_filename, "wb");

    if (!input_file || !output_file) {
        perror("File open failed");
        return;
    }

    unsigned char buffer[16];
    unsigned char plaintext[16];
    
    unsigned char current_block[16];
    

    size_t bytes_read;
    int is_last_block = 0;

    while (!is_last_block && (bytes_read = fread(buffer, 1, 16, input_file)) == 16) {
        
        // Reading the next block to check if this is the last one
        size_t next_read = fread(current_block, 1, 16, input_file);
        if (next_read < 16) {
            is_last_block = 1;  // If less than 16 bytes, it is the last block
        } else {
            fseek(input_file, -16, SEEK_CUR);  // Rewind if it's not the last block
        }

        AES_Decrypt(buffer, plaintext, w);  // Decrypt the current block
        
        if (is_last_block) {
            // Handle unpadding for the last block
            int plaintext_len = 16;  // Default length of the last block
            unpad_buffer(plaintext, &plaintext_len);  // Adjust the length by removing padding
            fwrite(plaintext, 1, plaintext_len, output_file);  // Write only unpadded plaintext
        } else {
            fwrite(plaintext, 1, 16, output_file);  // Write full 16 bytes for regular blocks
        }

        
    }

    fclose(input_file);
    fclose(output_file);
}

