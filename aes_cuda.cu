#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cuda_runtime.h>
#include <time.h>

// Benchmark parameters
#define MB_TO_TEST 1024  // Test 1GB of data
#define BLOCK_SIZE 16    // AES block size in bytes
// #define NUM_BLOCKS ((MB_TO_TEST * 1024 * 1024) / BLOCK_SIZE)
#define THREADS_PER_BLOCK 256
uint64_t NUM_BLOCKS = 128 * 1024 * 1024;

// AES parameters
#define Nb 4
#define Nk 4
#define Nr 10

// Error checking macro
#define CHECK_CUDA_ERROR(call) \
do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error in %s:%d: %s\n", \
                __FILE__, __LINE__, cudaGetErrorString(err)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

// Device constant memory for tables
__constant__ uint8_t d_sbox[256];
__constant__ uint8_t d_mul2[256];
__constant__ uint8_t d_mul3[256];
__constant__ uint8_t d_Rcon[11];

typedef struct {
    uint8_t nonce[8];    // 64-bit nonce
    uint8_t counter[8];  // 64-bit counter
} ctr_block_t;

// Host-side tables
static const uint8_t h_sbox[256] = {
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

// Host-side multiplication tables
static const uint8_t h_mul2[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};
static const uint8_t h_mul3[256] = {
    0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
    0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
    0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
    0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
    0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
    0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
    0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
    0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
    0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
    0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
    0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
    0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
    0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
    0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
    0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
    0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
};
static const uint8_t h_Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

__host__ void increment_counter(uint8_t* counter) {
    for (int i = 7; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

__device__ void increment_counter_device(uint8_t* counter) {
    for (int i = 7; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

__device__ void set_counter_value(uint8_t* counter, uint64_t value) {
    counter[7] = value & 0xFF;
    counter[6] = (value >> 8) & 0xFF;
    counter[5] = (value >> 16) & 0xFF;
    counter[4] = (value >> 24) & 0xFF;
    counter[3] = (value >> 32) & 0xFF;
    counter[2] = (value >> 40) & 0xFF;
    counter[1] = (value >> 48) & 0xFF;
    counter[0] = (value >> 56) & 0xFF;
}

// Modified CUDA kernel for CTR mode
__global__ void AES_Encrypt_CTR_Kernel(uint8_t* input, const uint8_t* roundKey, 
                                     uint8_t* output, int num_blocks, 
                                     const uint8_t* base_nonce, const uint8_t* base_counter) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;
    if (idx >= num_blocks) return;

    // Create local counter block
    uint8_t counter_block[16];
    
    // Copy nonce (first 8 bytes)
    for (int i = 0; i < 8; i++) {
        counter_block[i] = base_nonce[i];
    }
    
    // Calculate counter value directly
    uint64_t base_counter_value = 0;
    for (int i = 0; i < 8; i++) {
        base_counter_value = (base_counter_value << 8) | base_counter[i];
    }
    uint64_t new_counter_value = base_counter_value + idx;
    set_counter_value(counter_block + 8, new_counter_value);

    // Create state array for AES operation
    uint8_t state[4][4];
    uint8_t keystream[16];

    // Copy counter block to state array
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = counter_block[i * 4 + j];
        }
    }

    // Initial round
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= roundKey[i * 4 + j];
        }
    }

    // Main rounds
    for (int round = 1; round < Nr; round++) {
        // SubBytes
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = d_sbox[state[i][j]];
            }
        }

        // ShiftRows
        uint8_t temp;
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;

        // MixColumns
        uint8_t temp_state[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                temp_state[j][i] = state[j][i];
            }
        }

        for (int i = 0; i < 4; i++) {
            state[0][i] = d_mul2[temp_state[0][i]] ^ d_mul3[temp_state[1][i]] ^ 
                         temp_state[2][i] ^ temp_state[3][i];
            state[1][i] = temp_state[0][i] ^ d_mul2[temp_state[1][i]] ^ 
                         d_mul3[temp_state[2][i]] ^ temp_state[3][i];
            state[2][i] = temp_state[0][i] ^ temp_state[1][i] ^ 
                         d_mul2[temp_state[2][i]] ^ d_mul3[temp_state[3][i]];
            state[3][i] = d_mul3[temp_state[0][i]] ^ temp_state[1][i] ^ 
                         temp_state[2][i] ^ d_mul2[temp_state[3][i]];
        }

        // AddRoundKey
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] ^= roundKey[round * 16 + i * 4 + j];
            }
        }
    }

    // Final round
    // SubBytes
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = d_sbox[state[i][j]];
        }
    }

    // ShiftRows
    uint8_t temp;
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;

    // AddRoundKey
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= roundKey[Nr * 16 + i * 4 + j];
        }
    }

    // Copy state to keystream
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keystream[i * 4 + j] = state[j][i];
        }
    }

    // XOR keystream with input to create output
    uint8_t* block_input = input + (idx * 16);
    uint8_t* block_output = output + (idx * 16);
    for (int i = 0; i < 16; i++) {
        block_output[i] = block_input[i] ^ keystream[i];
    }
}

void KeyExpansion(uint8_t* key, uint8_t* roundKey) {
    uint8_t temp[4];
    
    // First round key is the original key
    for(int i = 0; i < Nk * 4; i++) {
        roundKey[i] = key[i];
    }
    
    // Generate round keys
    int i = Nk;
    while(i < Nb * (Nr + 1)) {
        // Copy last 4 bytes to temp
        for(int j = 0; j < 4; j++) {
            temp[j] = roundKey[(i - 1) * 4 + j];
        }
        
        if(i % Nk == 0) {
            // Rotate word
            uint8_t k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            // Apply S-box
            for(int j = 0; j < 4; j++) {
                temp[j] = h_sbox[temp[j]];
            }
            
            // XOR with round constant
            temp[0] = temp[0] ^ h_Rcon[i/Nk];
        }
        
        // XOR with previous round key
        for(int j = 0; j < 4; j++) {
            roundKey[i * 4 + j] = roundKey[(i - Nk) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

// Modified host function to run AES-CTR encryption on GPU
void AES_Encrypt_CTR_CUDA(uint8_t* input, uint8_t* key, uint8_t* output, 
                         int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t roundKey[176];  // 11 round keys (176 bytes)
    KeyExpansion(key, roundKey);

    // Allocate device memory
    uint8_t *d_input, *d_output, *d_roundKey, *d_nonce, *d_counter;
    
    CHECK_CUDA_ERROR(cudaMalloc(&d_input, num_blocks * 16));
    CHECK_CUDA_ERROR(cudaMalloc(&d_output, num_blocks * 16));
    CHECK_CUDA_ERROR(cudaMalloc(&d_roundKey, 176));
    CHECK_CUDA_ERROR(cudaMalloc(&d_nonce, 8));
    CHECK_CUDA_ERROR(cudaMalloc(&d_counter, 8));

    // Copy data to device
    CHECK_CUDA_ERROR(cudaMemcpy(d_input, input, num_blocks * 16, cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_roundKey, roundKey, 176, cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_nonce, initial_ctr->nonce, 8, cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_counter, initial_ctr->counter, 8, cudaMemcpyHostToDevice));

    // Copy lookup tables to constant memory
    CHECK_CUDA_ERROR(cudaMemcpyToSymbol(d_sbox, h_sbox, sizeof(h_sbox)));
    CHECK_CUDA_ERROR(cudaMemcpyToSymbol(d_mul2, h_mul2, sizeof(h_mul2)));
    CHECK_CUDA_ERROR(cudaMemcpyToSymbol(d_mul3, h_mul3, sizeof(h_mul3)));

    // Calculate grid dimensions
    int threadsPerBlock = THREADS_PER_BLOCK;
    int blocksPerGrid = (num_blocks + threadsPerBlock - 1) / threadsPerBlock;

    // Launch kernel
    AES_Encrypt_CTR_Kernel<<<blocksPerGrid, threadsPerBlock>>>(
        d_input, d_roundKey, d_output, num_blocks, d_nonce, d_counter);
    CHECK_CUDA_ERROR(cudaGetLastError());

    // Copy result back to host
    CHECK_CUDA_ERROR(cudaMemcpy(output, d_output, num_blocks * 16, cudaMemcpyDeviceToHost));

    // Free device memory
    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_roundKey);
    cudaFree(d_nonce);
    cudaFree(d_counter);
}


void AES_Encrypt_Serial_CTR(uint8_t* input, uint8_t* key, uint8_t* output, 
                           int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t roundKey[176];
    KeyExpansion(key, roundKey);
    
    uint8_t counter_block[16];
    uint8_t keystream[16];
    ctr_block_t current_ctr = *initial_ctr;
    
    for(int block = 0; block < num_blocks; block++) {
        // Set up counter block
        memcpy(counter_block, current_ctr.nonce, 8);
        memcpy(counter_block + 8, current_ctr.counter, 8);
        
        // Encrypt counter block to generate keystream
        uint8_t state[4][4];
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[j][i] = counter_block[i * 4 + j];
            }
        }
        
        // Initial round
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[j][i] ^= roundKey[i * 4 + j];
            }
        }
        
        // Main rounds
        for(int round = 1; round < Nr; round++) {
            // SubBytes
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    state[i][j] = h_sbox[state[i][j]];
                }
            }
            
            // ShiftRows
            uint8_t temp;
            temp = state[1][0];
            state[1][0] = state[1][1];
            state[1][1] = state[1][2];
            state[1][2] = state[1][3];
            state[1][3] = temp;
            
            temp = state[2][0];
            state[2][0] = state[2][2];
            state[2][2] = temp;
            temp = state[2][1];
            state[2][1] = state[2][3];
            state[2][3] = temp;
            
            temp = state[3][3];
            state[3][3] = state[3][2];
            state[3][2] = state[3][1];
            state[3][1] = state[3][0];
            state[3][0] = temp;
            
            // MixColumns
            uint8_t temp_state[4][4];
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    temp_state[j][i] = state[j][i];
                }
            }
            
            for(int i = 0; i < 4; i++) {
                state[0][i] = h_mul2[temp_state[0][i]] ^ h_mul3[temp_state[1][i]] ^ 
                             temp_state[2][i] ^ temp_state[3][i];
                state[1][i] = temp_state[0][i] ^ h_mul2[temp_state[1][i]] ^ 
                             h_mul3[temp_state[2][i]] ^ temp_state[3][i];
                state[2][i] = temp_state[0][i] ^ temp_state[1][i] ^ 
                             h_mul2[temp_state[2][i]] ^ h_mul3[temp_state[3][i]];
                state[3][i] = h_mul3[temp_state[0][i]] ^ temp_state[1][i] ^ 
                             temp_state[2][i] ^ h_mul2[temp_state[3][i]];
            }
            
            // AddRoundKey
            for(int i = 0; i < 4; i++) {
                for(int j = 0; j < 4; j++) {
                    state[j][i] ^= roundKey[round * 16 + i * 4 + j];
                }
            }
        }
        
        // Final round
        // SubBytes
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[i][j] = h_sbox[state[i][j]];
            }
        }
        
        // ShiftRows
        uint8_t temp;
        temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;
        
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;
        
        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
        
        // AddRoundKey
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                state[j][i] ^= roundKey[Nr * 16 + i * 4 + j];
            }
        }

        // Copy state to keystream
        for(int i = 0; i < 4; i++) {
            for(int j = 0; j < 4; j++) {
                keystream[i * 4 + j] = state[j][i];
            }
        }

        // XOR keystream with input to get output
        uint8_t* block_input = input + (block * 16);
        uint8_t* block_output = output + (block * 16);
        for(int i = 0; i < 16; i++) {
            block_output[i] = block_input[i] ^ keystream[i];
        }
        
        // Increment counter
        increment_counter(current_ctr.counter);
    }
}

// Function to compare two buffers
int compare_buffers(uint8_t* buf1, uint8_t* buf2, size_t size) {
    for(size_t i = 0; i < size; i++) {
        if(buf1[i] != buf2[i]) {
            printf("Mismatch at position %zu: %02x != %02x\n", i, buf1[i], buf2[i]);
            return 0;
        }
    }
    return 1;
}

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
    
    // Allocate host memory with page-locked memory for better transfer performance
    uint8_t *input, *output_gpu, *output_cpu;
    CHECK_CUDA_ERROR(cudaMallocHost(&input, NUM_BLOCKS * 16));
    CHECK_CUDA_ERROR(cudaMallocHost(&output_gpu, NUM_BLOCKS * 16));
    CHECK_CUDA_ERROR(cudaMallocHost(&output_cpu, NUM_BLOCKS * 16));
    
    // Initialize input data
    for(int i = 0; i < NUM_BLOCKS * 16; i++) {
        input[i] = i & 0xFF;
    }
    
    // Get device properties
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("Using GPU: %s\n", prop.name);
    
    AES_Encrypt_CTR_CUDA(input, key, output_gpu, NUM_BLOCKS, &initial_ctr);
    
    // Benchmark GPU version
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    
    cudaEventRecord(start);
    AES_Encrypt_CTR_CUDA(input, key, output_gpu, NUM_BLOCKS, &initial_ctr);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    
    float gpu_milliseconds = 0;
    cudaEventElapsedTime(&gpu_milliseconds, start, stop);
    double gpu_seconds = gpu_milliseconds / 1000.0;
    
    // Benchmark CPU version
    clock_t cpu_start = clock();
    AES_Encrypt_Serial_CTR(input, key, output_cpu, NUM_BLOCKS, &initial_ctr);
    clock_t cpu_end = clock();
    double cpu_seconds = (double)(cpu_end - cpu_start) / CLOCKS_PER_SEC;
    
    // Compare results
    printf("Results match: %s\n", 
           compare_buffers(output_cpu, output_gpu, NUM_BLOCKS * 16) ? "Yes" : "No");
    
    // Print first block comparison if there's a mismatch
    if (!compare_buffers(output_cpu, output_gpu, NUM_BLOCKS * 16)) {
        printf("\nFirst block comparison:\nCPU: ");
        for(int i = 0; i < 16; i++) {
            printf("%02x ", output_cpu[i]);
        }
        printf("\nGPU: ");
        for(int i = 0; i < 16; i++) {
            printf("%02x ", output_gpu[i]);
        }
        printf("\n");
    }
    
    // Calculate and print performance metrics
    double data_size_gb = (double)(NUM_BLOCKS * BLOCK_SIZE) / (1024 * 1024 * 1024);
    printf("\nPerformance Comparison:\n");
    printf("Data size: %.2f GB\n", data_size_gb);
    printf("CPU Time: %.4f seconds (%.2f GB/s)\n", 
           cpu_seconds, data_size_gb / cpu_seconds);
    printf("GPU Time: %.4f seconds (%.2f GB/s)\n", 
           gpu_seconds, data_size_gb / gpu_seconds);
    printf("Speedup: %.2fx\n", cpu_seconds / gpu_seconds);
    
    // Clean up
    cudaFreeHost(input);
    cudaFreeHost(output_gpu);
    cudaFreeHost(output_cpu);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    
    return 0;
}