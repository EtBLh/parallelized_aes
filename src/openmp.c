#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdlib.h>

#include "openmp.h"

void aesctr_enc_openmp(uint8_t* input, uint8_t* roundKey, uint8_t* output, int num_blocks, ctr_block_t* initial_ctr) {
    uint64_t base_counter = 0;
    for(int i = 0; i < 8; i++) {
        base_counter = (base_counter << 8) | initial_ctr->counter[i];
    }

    #pragma omp parallel
    {
        uint8_t counter_block[16] __attribute__((aligned(16)));
        uint8_t keystream[16] __attribute__((aligned(16)));
        
        #pragma omp for schedule(dynamic, 256)
        for(int block = 0; block < num_blocks; block++) {
            uint64_t counter_value = base_counter + block;
            
            // Setup counter block
            setup_counter_block(counter_block, initial_ctr->nonce, counter_value);
            
            // Encrypt counter block
            // AES_Encrypt_Block(counter_block, roundKey, keystream);
            aes_enc1block_serial(counter_block, roundKey, keystream);

            
            // XOR using 64-bit operations
            uint64_t* block_input = (uint64_t*)(input + (block * 16));
            uint64_t* block_output = (uint64_t*)(output + (block * 16));
            uint64_t* ks = (uint64_t*)keystream;
            
            block_output[0] = block_input[0] ^ ks[0];
            block_output[1] = block_input[1] ^ ks[1];
        }
    }
}