#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "pthread.h"

void* thread_worker(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    uint8_t counter_block[16];
    
    // Encrypt assigned blocks
    for(size_t i = 0; i < data->num_blocks; i++) {
        size_t block_idx = data->start_block + i;
        prepare_ctr_block(data->initial_counter, counter_block, block_idx);
        
        aesctr_enc1block_serial(
            counter_block,
            data->input + (block_idx * BLOCK_SIZE),
            data->key_schedule,
            data->output + (block_idx * BLOCK_SIZE));
    }
    
    return NULL;
}

void aesctr_enc_pthread(uint8_t* input, uint8_t* key_schedule, uint8_t* output, size_t total_blocks, ctr_block_t* initial_ctr) {
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    // Calculate blocks per thread
    size_t blocks_per_thread = total_blocks / NUM_THREADS;
    size_t remaining_blocks = total_blocks % NUM_THREADS;
    size_t current_block = 0;
    
    // Create and launch threads
    for(int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].input = input;
        thread_data[i].output = output;
        thread_data[i].key_schedule = key_schedule;
        thread_data[i].start_block = current_block;
        thread_data[i].num_blocks = blocks_per_thread + (i < remaining_blocks ? 1 : 0);
        thread_data[i].initial_counter = initial_ctr;
        
        pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]);
        current_block += thread_data[i].num_blocks;
    }
    
    // Wait for all threads
    for(int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
}

