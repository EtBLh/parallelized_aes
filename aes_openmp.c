#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <stdlib.h>

#define Nb 4
#define Nk 4
#define Nr 10
// Benchmark parameters
#define MB_TO_TEST 1024  // Test 1GB of data
#define BLOCK_SIZE 16   // AES block size in bytes
#define NUM_BLOCKS ((MB_TO_TEST * 1024 * 1024) / BLOCK_SIZE) // Number of blocks to process

// Add CTR mode specific structure
typedef struct {
    uint8_t nonce[8];    // 64-bit nonce
    uint8_t counter[8];  // 64-bit counter
} ctr_block_t;

typedef uint8_t state_t[4][4];

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

// Galois Field multiplication tables
static const uint8_t mul2[256] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    // ... (rest would be filled with proper GF(2^8) multiplication values)
};

static const uint8_t mul3[256] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    // ... (rest would be filled with proper GF(2^8) multiplication values)
};


// Function to increment counter
void increment_counter(uint8_t* counter) {
    for (int i = 7; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

void setup_counter_block(ctr_block_t* base_ctr, uint8_t* counter_block, uint64_t block_idx) {
    // Copy nonce
    memcpy(counter_block, base_ctr->nonce, 8);
    
    // Calculate counter value directly
    uint64_t counter_value = *(uint64_t*)base_ctr->counter + block_idx;
    
    // Store counter value in big-endian format
    for(int i = 7; i >= 0; i--) {
        counter_block[8 + i] = counter_value & 0xFF;
        counter_value >>= 8;
    }
}

void KeyExpansion(uint8_t* key, uint8_t* roundKey) {
    uint8_t temp[4], k;
    
    memcpy(roundKey, key, Nk * 4);
    
    for(int i = Nk; i < Nb * (Nr + 1); i++) {
        for(int j = 0; j < 4; j++)
            temp[j] = roundKey[(i-1) * 4 + j];
        
        if(i % Nk == 0) {
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            
            for(int j = 0; j < 4; j++)
                temp[j] = sbox[temp[j]];
            
            temp[0] ^= Rcon[i/Nk];
        }
        
        for(int j = 0; j < 4; j++)
            roundKey[i * 4 + j] = roundKey[(i-Nk) * 4 + j] ^ temp[j];
    }
}

void AddRoundKey(state_t* state, const uint8_t* roundKey, int round) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            (*state)[j][i] ^= roundKey[round * 16 + i * 4 + j];
        }
    }
}

void SubBytes(state_t* state) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            (*state)[i][j] = sbox[(*state)[i][j]];
        }
    }
}

void ShiftRows(state_t* state) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = (*state)[1][0];
    (*state)[1][0] = (*state)[1][1];
    (*state)[1][1] = (*state)[1][2];
    (*state)[1][2] = (*state)[1][3];
    (*state)[1][3] = temp;
    
    // Row 2: shift left by 2
    temp = (*state)[2][0];
    (*state)[2][0] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[2][1];
    (*state)[2][1] = (*state)[2][3];
    (*state)[2][3] = temp;
    
    // Row 3: shift left by 3 (same as right by 1)
    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][0];
    (*state)[3][0] = temp;
}

// Corrected MixColumns using pre-computed tables
void MixColumns(state_t* state) {
    uint8_t temp[4];
    
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            temp[j] = (*state)[j][i];
        }
        
        (*state)[0][i] = mul2[temp[0]] ^ mul3[temp[1]] ^ temp[2] ^ temp[3];
        (*state)[1][i] = temp[0] ^ mul2[temp[1]] ^ mul3[temp[2]] ^ temp[3];
        (*state)[2][i] = temp[0] ^ temp[1] ^ mul2[temp[2]] ^ mul3[temp[3]];
        (*state)[3][i] = mul3[temp[0]] ^ temp[1] ^ temp[2] ^ mul2[temp[3]];
    }
}

void AES_Encrypt_Block(uint8_t* input, const uint8_t* roundKey, uint8_t* output) {
    state_t state;
    memcpy(&state, input, 16);
    
    // Initial round
    AddRoundKey(&state, roundKey, 0);
    
    // Main rounds
    for(int round = 1; round < Nr; round++) {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(&state, roundKey, round);
    }
    
    // Final round
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, roundKey, Nr);
    
    memcpy(output, &state, 16);
}

void AES_Encrypt_Block_CTR(uint8_t* counter_block, uint8_t* input, 
                          const uint8_t* roundKey, uint8_t* output) {
    uint8_t keystream[16];
    
    // Encrypt the counter block to create keystream
    AES_Encrypt_Block(counter_block, roundKey, keystream);
    
    // XOR input with keystream to create output
    for(int i = 0; i < 16; i++) {
        output[i] = input[i] ^ keystream[i];
    }
}

void AES_Encrypt_Serial_CTR(uint8_t* input, const uint8_t* roundKey, 
                           uint8_t* output, int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t counter_block[16];
    
    for(int i = 0; i < num_blocks; i++) {
        setup_counter_block(initial_ctr, counter_block, i);
        AES_Encrypt_Block_CTR(counter_block, input + (i * 16), 
                             roundKey, output + (i * 16));
    }
}

void AES_Encrypt_Parallel_CTR(uint8_t* input, const uint8_t* roundKey, 
                             uint8_t* output, int num_blocks, ctr_block_t* initial_ctr) {
    int max_threads = omp_get_max_threads();
    printf("Available threads: %d\n", max_threads);
    
    // Set number of threads explicitly
    omp_set_num_threads(max_threads);

    #pragma omp parallel
    {
        uint8_t counter_block[16];
        
        #pragma omp parallel for schedule(static)  // dynamic scheduling with chunk size 64
        for(int i = 0; i < num_blocks; i++) {
            setup_counter_block(initial_ctr, counter_block, i);
            AES_Encrypt_Block_CTR(counter_block, input + (i * 16), 
                                roundKey, output + (i * 16));
        }
    }
}

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
    KeyExpansion(key, roundKey);
    
    // Warm up the cache
    uint8_t temp_counter[16];
    setup_counter_block(&initial_ctr, temp_counter, 0);
    for(int i = 0; i < 1000; i++) {
        AES_Encrypt_Block_CTR(temp_counter, input, roundKey, output_serial);
    }
    
    // Serial encryption
    double start_time = omp_get_wtime();
    AES_Encrypt_Serial_CTR(input, roundKey, output_serial, NUM_BLOCKS, &initial_ctr);
    double serial_time = omp_get_wtime() - start_time;
    
    // Parallel encryption
    start_time = omp_get_wtime();
    AES_Encrypt_Parallel_CTR(input, roundKey, output_parallel, NUM_BLOCKS, &initial_ctr);
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
