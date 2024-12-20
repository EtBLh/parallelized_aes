#include "aes.h"

int main() {
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    ctr_block_t initial_ctr = {
        .nonce = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
        .counter = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };
    
    // Aligned memory allocation
    uint8_t *input = (uint8_t*)aligned_alloc(16, NUM_BLOCKS * 16);
    uint8_t *output_serial = (uint8_t*)aligned_alloc(16, NUM_BLOCKS * 16);
    uint8_t *roundKey = (uint8_t*)aligned_alloc(16, 176);
    
    if (!input || !output_serial || !roundKey) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    
    // Initialize input
    for(int i = 0; i < NUM_BLOCKS * 16; i++) {
        input[i] = i & 0xFF;
    }
    
    aes_keyexpansion_serial(key, roundKey);
    
    // Warm up
    aesctr_enc_serial(input, roundKey, output_serial, 1, &initial_ctr);
    
    // Serial encryption
    clock_t start = clock();
    aes_keyexpansion_serial(key, roundKey);
    aesctr_enc_serial(input, roundKey, output_serial, NUM_BLOCKS, &initial_ctr);
    double serial_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    
    // Calculate throughput
    double data_size_gb = (double)(NUM_BLOCKS * BLOCK_SIZE) / (1024 * 1024 * 1024);
    
    printf("Data size: %.2f GB\n", data_size_gb);
    printf("Serial Time: %.4f seconds (%.2f GB/s)\n",
           serial_time, data_size_gb / serial_time);
    
    printf("\n");
    
    // Clean up
    free(input);
    free(output_serial);
    free(roundKey);
    
    return 0;
}