#include "aes.h"
#include "openmp.h"

int main() {
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    omp_set_num_threads(NUM_THREADS);
    
    // Aligned memory allocation
    uint8_t *input = (uint8_t*)aligned_alloc(64, NUM_BLOCKS * 16);
    uint8_t *output_serial = (uint8_t*)aligned_alloc(64, NUM_BLOCKS * 16);
    uint8_t *output_parallel = (uint8_t*)aligned_alloc(64, NUM_BLOCKS * 16);
    uint8_t *roundKey = (uint8_t*)aligned_alloc(64, 176); // 11 round keys
    
    if (!input || !output_serial || !output_parallel || !roundKey) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    
    // Initialize input
    for(int i = 0; i < NUM_BLOCKS * 16; i++) {
        input[i] = i & 0xFF;
    }
    

    ctr_block_t initial_ctr = {
        .nonce = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
        .counter = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };
    // Key expansion
    aes_keyexpansion_serial(key, roundKey);
    
    // Warm up the cache
    uint8_t temp_counter[16];
    
    setup_counter_block(temp_counter, initial_ctr.nonce, 0);
    for(int i = 0; i < 1000; i++) {
        aesctr_enc1block_serial(temp_counter, input, roundKey, output_serial);
    }
    
    // Serial encryption
    double start_time = omp_get_wtime();
    aes_keyexpansion_serial(key, roundKey);
    aesctr_enc_serial(input, roundKey, output_serial, NUM_BLOCKS, &initial_ctr);
    double serial_time = omp_get_wtime() - start_time;
    
    // Parallel encryption
    start_time = omp_get_wtime();
    aes_keyexpansion_serial(key, roundKey);
    aesctr_enc_openmp(input, roundKey, output_parallel, NUM_BLOCKS, &initial_ctr);
    double parallel_time = omp_get_wtime() - start_time;
    
    // Verify results
    printf("Results match: %s\n", 
           compare_buffers(output_serial, output_parallel, NUM_BLOCKS * 16) ? "Yes" : "No");
    
    // Calculate throughput
    double data_size_gb = (double)(NUM_BLOCKS * BLOCK_SIZE) / (1024 * 1024 * 1024);
    
    printf("Data size: %.2f GB\n", data_size_gb);
    printf("Serial Time: %.4f seconds (%.2f GB/s)\n", 
           serial_time, data_size_gb / serial_time);
    printf("Parallel Time: %.4f seconds (%.2f GB/s)\n", 
           parallel_time, data_size_gb / parallel_time);
    printf("Speedup: %.2fx\n", serial_time / parallel_time);
    
    // Print number of threads used
    #pragma omp parallel
    {
        #pragma omp single
        printf("Number of threads used: %d\n", omp_get_num_threads());
    }
    
    printf("\nFirst block comparison:\nSerial: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", output_serial[i]);
    }
    printf("\nParallel: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", output_parallel[i]);
    }
    printf("\n");
    
    // Clean up
    free(input);
    free(output_serial);
    free(output_parallel);
    free(roundKey);
    
    return 0;
}