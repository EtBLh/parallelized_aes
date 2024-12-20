#ifndef AES_PTHREAD_H
#define AES_PTHREAD_H

#include "aes.h"

// Structure to pass data to threads
typedef struct {
    uint8_t* input;
    uint8_t* output;
    uint8_t* key_schedule;
    ctr_block_t* initial_counter;  // Initial counter value for this thread
    size_t start_block;
    size_t num_blocks;
} thread_data_t;

void aesctr_enc_pthread(uint8_t* input, uint8_t* roundKey, uint8_t* output, size_t total_blocks, ctr_block_t* initial_ctr);

#endif