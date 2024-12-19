#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

// AES parameters
#define Nb 4
#define Nk 4
#define Nr 10
#define BLOCK_SIZE 16
#define NUM_THREADS 8

// Calculate blocks for 1GB
// 1GB = 1024 * 1024 * 1024 bytes
// Number of blocks = 1GB / BLOCK_SIZE
#define ONE_GB (1024ULL * 1024ULL * 1024ULL)
#define NUM_BLOCKS (ONE_GB / BLOCK_SIZE)

typedef uint8_t state_t[4][4];
static uint8_t RoundKey[240];
pthread_mutex_t key_mutex = PTHREAD_MUTEX_INITIALIZER;
int key_initialized = 0;

typedef struct {
    uint8_t nonce[8];    // 64-bit nonce
    uint8_t counter[8];  // 64-bit counter
} ctr_block_t;

// Structure to pass data to threads
typedef struct {
    uint8_t* input;
    uint8_t* output;
    uint8_t* key;
    ctr_block_t initial_counter;  // Initial counter value for this thread
    size_t start_block;
    size_t num_blocks;
    uint8_t local_round_key[240];
} thread_data_t;


// The S-box table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// The Rcon table
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

void increment_counter(ctr_block_t* ctr) {
    for (int i = 7; i >= 0; i--) {
        if (++ctr->counter[i] != 0) {
            break;
        }
    }
}


// Key Expansion function
void KeyExpansion(uint8_t* key, uint8_t* roundKey) {
    uint8_t temp[4], k;
    
    // The first round key is the key itself
    for(int i = 0; i < Nk * 4; i++)
        roundKey[i] = key[i];
    
    // All other round keys are derived from previous round keys
    int i = Nk;
    while(i < Nb * (Nr + 1)) {
        for(int j = 0; j < 4; j++)
            temp[j] = roundKey[(i-1) * 4 + j];
        
        if(i % Nk == 0) {
            // Rotate word
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            
            temp[0] = temp[0] ^ Rcon[i/Nk];
        }
        
        for(int j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKey[(i-Nk) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

// AES core functions
void AddRoundKey(uint8_t round, state_t* state, uint8_t* roundKey) {
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            (*state)[i][j] ^= roundKey[round * Nb * 4 + i * Nb + j];
}

void SubBytes(state_t* state) {
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            (*state)[i][j] = sbox[(*state)[i][j]];
}

void ShiftRows(state_t* state) {
    uint8_t temp;
    
    // Rotate first row 1 columns to left  
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;

    // Rotate second row 2 columns to left  
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;

    // Rotate third row 3 columns to left
    temp = (*state)[3][0];
    (*state)[3][0] = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = temp;
}

void MixColumns(state_t* state) {
    uint8_t temp[4];
    for(int i = 0; i < 4; i++) {
        temp[0] = (*state)[0][i];
        temp[1] = (*state)[1][i];
        temp[2] = (*state)[2][i];
        temp[3] = (*state)[3][i];
        
        (*state)[0][i] = (temp[0] << 1) ^ (temp[1] << 1) ^ temp[1] ^ temp[2] ^ temp[3];
        (*state)[1][i] = temp[0] ^ (temp[1] << 1) ^ (temp[2] << 1) ^ temp[2] ^ temp[3];
        (*state)[2][i] = temp[0] ^ temp[1] ^ (temp[2] << 1) ^ (temp[3] << 1) ^ temp[3];
        (*state)[3][i] = (temp[0] << 1) ^ temp[0] ^ temp[1] ^ temp[2] ^ (temp[3] << 1);
    }
}

void AES_Encrypt_Block(uint8_t* input, uint8_t* output, uint8_t* roundKey) {
    state_t* state = (state_t*)input;
    uint8_t working_state[BLOCK_SIZE];
    memcpy(working_state, input, BLOCK_SIZE);
    state = (state_t*)working_state;
    
    // Initial round
    AddRoundKey(0, state, roundKey);
    
    // Main rounds
    for(uint8_t round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, roundKey);
    }
    
    // Final round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, roundKey);
    
    // Copy result to output
    memcpy(output, working_state, BLOCK_SIZE);
}

void* encrypt_blocks(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    
    // Create local copy of round key
    KeyExpansion(data->key, data->local_round_key);
    
    // Encrypt assigned blocks
    for(size_t i = 0; i < data->num_blocks; i++) {
        size_t block_idx = data->start_block + i;
        AES_Encrypt_Block(
            data->input + (block_idx * BLOCK_SIZE),
            data->output + (block_idx * BLOCK_SIZE),
            data->local_round_key
        );
    }
    
    return NULL;
}

void AES_Encrypt_Parallel(uint8_t* input, uint8_t* key, uint8_t* output, size_t total_blocks) {
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
        thread_data[i].key = key;
        thread_data[i].start_block = current_block;
        thread_data[i].num_blocks = blocks_per_thread + (i < remaining_blocks ? 1 : 0);
        
        pthread_create(&threads[i], NULL, encrypt_blocks, &thread_data[i]);
        current_block += thread_data[i].num_blocks;
    }
    
    // Wait for all threads
    for(int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
}

void AES_Encrypt_Serial(uint8_t* input, uint8_t* key, uint8_t* output, size_t total_blocks) {
    uint8_t roundKey[240];
    KeyExpansion(key, roundKey);
    
    for(size_t i = 0; i < total_blocks; i++) {
        AES_Encrypt_Block(
            input + (i * BLOCK_SIZE),
            output + (i * BLOCK_SIZE),
            roundKey
        );
    }
}

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
    AES_Encrypt_Serial(input, key, output_serial, NUM_BLOCKS);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double serial_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Serial time: %.3f seconds\n", serial_time);
    
    // Run parallel version
    printf("Running parallel encryption...\n");
    clock_gettime(CLOCK_MONOTONIC, &start);
    AES_Encrypt_Parallel(input, key, output_parallel, NUM_BLOCKS);
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
    pthread_mutex_destroy(&key_mutex);
    
    return 0;
}