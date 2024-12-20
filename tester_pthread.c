#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "aes.h"
#include "pthread.h"

int main() {
    // Test parameters for 1GB
    const size_t total_size = ONE_GB;
    printf("Benchmark parameters:\n");
    printf("Total data size: 1 GB\n");
    printf("Block size: %d bytes\n", BLOCK_SIZE);
    printf("Number of blocks: %zu\n", NUM_BLOCKS);
    printf("Number of threads: %d\n\n", NUM_THREADS);
    
    // Allocate memory
    printf("Allocating memory...\n");
    uint8_t* input = (uint8_t*)malloc(total_size);
    uint8_t* output_serial = (uint8_t*)malloc(total_size);
    uint8_t* output_parallel = (uint8_t*)malloc(total_size);
    uint8_t *roundKey = (uint8_t*)aligned_alloc(64, 176); // 11 round keys

    
    if (!input || !output_serial || !output_parallel) {
        printf("Failed to allocate memory!\n");
        return 1;
    }
    
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
    
    // Initialize input with random data
    printf("Initializing input data...\n");
    srand(time(NULL));
    for(size_t i = 0; i < total_size; i++) {
        input[i] = rand() % 256;
    }
    
    // Run serial version
    printf("Running serial encryption...\n");
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    aes_keyexpansion_serial(key, roundKey);
    aesctr_enc_serial(input, roundKey, output_serial, NUM_BLOCKS, initial_ctr);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double serial_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Serial time: %.3f seconds\n", serial_time);
    
    // Run parallel version
    printf("Running parallel encryption...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    aes_keyexpansion_serial(key, roundKey);
    aesctr_enc_pthread(input, roundKey, output_parallel, NUM_BLOCKS, initial_ctr);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double parallel_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Parallel time (%d threads): %.3f seconds\n", NUM_THREADS, parallel_time);
    
    // Calculate speedup and throughput
    double speedup = serial_time / parallel_time;
    double efficiency = (speedup / NUM_THREADS) * 100;
    double serial_throughput = (ONE_GB / (1024.0 * 1024.0 * 1024.0)) / serial_time;    // GB/s
    double parallel_throughput = (ONE_GB / (1024.0 * 1024.0 * 1024.0)) / parallel_time; // GB/s
    
    printf("\nPerformance metrics:\n");
    printf("Speedup: %.2fx\n", speedup);
    printf("Parallel efficiency: %.1f%%\n", efficiency);
    printf("Serial throughput: %.2f GB/s\n", serial_throughput);
    printf("Parallel throughput: %.2f GB/s\n", parallel_throughput);
    
    // Verify results
    printf("\nVerifying results...\n");
    int mismatch = 0;
    for(size_t i = 0; i < total_size; i++) {
        if(output_serial[i] != output_parallel[i]) {
            printf("Mismatch at index %zu: serial=%02x, parallel=%02x\n", 
                   i, output_serial[i], output_parallel[i]);
            mismatch = 1;
            break;
        }
    }
    printf("Results match: %s\n", mismatch ? "No" : "Yes");
    
    // Clean up
    printf("Cleaning up...\n");
    free(input);
    free(output_serial);
    free(output_parallel);
    free(roundKey);
    pthread_mutex_destroy(&key_mutex);
    
    return 0;
}