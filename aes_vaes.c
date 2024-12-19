#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <wmmintrin.h>  // AES-NI intrinsics
#include <immintrin.h>  // AES-NI intrinsics
#include <cpuid.h>      // for checking AES-NI support

#define Nb 4
#define Nk 4
#define Nr 10
#define MB_TO_TEST 1024
#define BLOCK_SIZE 16
#define NUM_BLOCKS ((MB_TO_TEST * 1024 * 1024) / BLOCK_SIZE)

typedef uint8_t state_t[4][4];
typedef struct {
    uint8_t nonce[8];    // 64-bit nonce
    uint8_t counter[8];  // 64-bit counter
} ctr_block_t;

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

static const uint8_t mul2[256] = {
    0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
    0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
    0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
    0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
    0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
    0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
    0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
    0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
    0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
    0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
    0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
    0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
    0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
    0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
    0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
    0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

static const uint8_t mul3[256] = {
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

static inline void increment_counter(uint8_t* counter) {
    for (int i = 7; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}

static inline void set_counter_value(uint8_t* counter, uint64_t value) {
    counter[7] = value & 0xFF;
    counter[6] = (value >> 8) & 0xFF;
    counter[5] = (value >> 16) & 0xFF;
    counter[4] = (value >> 24) & 0xFF;
    counter[3] = (value >> 32) & 0xFF;
    counter[2] = (value >> 40) & 0xFF;
    counter[1] = (value >> 48) & 0xFF;
    counter[0] = (value >> 56) & 0xFF;
}

// Modified state handling functions
void state_in(state_t* state, const uint8_t* input) {
    for(int col = 0; col < 4; col++) {
        for(int row = 0; row < 4; row++) {
            (*state)[row][col] = input[col * 4 + row];
        }
    }
}

void state_out(const state_t* state, uint8_t* output) {
    for(int col = 0; col < 4; col++) {
        for(int row = 0; row < 4; row++) {
            output[col * 4 + row] = (*state)[row][col];
        }
    }
}

static inline void prepare_ctr_block(ctr_block_t* base_ctr, uint8_t* counter_block, uint64_t block_idx) {
    // Copy nonce
    memcpy(counter_block, base_ctr->nonce, 8);
    
    // Get base counter value
    uint64_t counter_value = 0;
    for (int i = 0; i < 8; i++) {
        counter_value = (counter_value << 8) | base_ctr->counter[i];
    }
    
    // Add block index and set new counter value
    counter_value += block_idx;
    set_counter_value(counter_block + 8, counter_value);
}

static __m128i AES_128_key_expansion_assist(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    return _mm_xor_si128(temp1, temp2);
}

// Check for AES-NI support
int check_aesni_support() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
    return 0;
}

void KeyExpansion(uint8_t* key, uint8_t* roundKey) {
    uint32_t* w = (uint32_t*)roundKey;
    uint32_t temp;

    // First round key is the key itself
    for(int i = 0; i < Nk; i++) {
        w[i] = ((uint32_t)key[4*i] << 24) | 
               ((uint32_t)key[4*i+1] << 16) | 
               ((uint32_t)key[4*i+2] << 8) | 
               ((uint32_t)key[4*i+3]);
    }

    // Generate round keys
    for(int i = Nk; i < Nb * (Nr + 1); i++) {
        temp = w[i-1];
        
        if(i % Nk == 0) {
            // RotWord
            temp = ((temp << 8) | (temp >> 24));
            
            // SubWord
            temp = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                  ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                  ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                  ((uint32_t)sbox[temp & 0xFF]);
            
            temp ^= ((uint32_t)Rcon[i/Nk] << 24);
        }
        
        w[i] = w[i-Nk] ^ temp;
    }

    // Convert words to bytes in AES-NI compatible format
    for(int i = 0; i < Nb * (Nr + 1); i++) {
        uint32_t temp = w[i];
        for(int j = 0; j < 4; j++) {
            roundKey[i*4 + j] = (temp >> (24 - 8*j)) & 0xFF;
        }
    }
}


void AddRoundKey(state_t* state, const uint8_t* roundKey, int round) {
    for(int col = 0; col < 4; col++) {
        for(int row = 0; row < 4; row++) {
            (*state)[row][col] ^= roundKey[round * 16 + col * 4 + row];
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

void MixColumns(state_t* state) {
    uint8_t temp[4];
    uint8_t result[4];
    
    for(int i = 0; i < 4; i++) {
        // Copy current column
        for(int j = 0; j < 4; j++) {
            temp[j] = (*state)[j][i];
        }
        
        // Calculate new column values
        result[0] = mul2[temp[0]] ^ mul3[temp[1]] ^ temp[2] ^ temp[3];
        result[1] = temp[0] ^ mul2[temp[1]] ^ mul3[temp[2]] ^ temp[3];
        result[2] = temp[0] ^ temp[1] ^ mul2[temp[2]] ^ mul3[temp[3]];
        result[3] = mul3[temp[0]] ^ temp[1] ^ temp[2] ^ mul2[temp[3]];
        
        // Update state with new values
        for(int j = 0; j < 4; j++) {
            (*state)[j][i] = result[j];
        }
    }
}
// AES-NI version of key expansion
void KeyExpansion_AES_NI(uint8_t* userkey, __m128i* key_schedule) {
    __m128i temp1 = _mm_loadu_si128((__m128i*)userkey);
    __m128i temp2;
    
    key_schedule[0] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[1] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[2] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[3] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[4] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[5] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[6] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[7] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[8] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[9] = temp1;
    
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_key_expansion_assist(temp1, temp2);
    key_schedule[10] = temp1;
}

void AES_Encrypt_Block(uint8_t* input, const uint8_t* roundKey, uint8_t* output) {
    state_t state;
    
    // Input transformation
    state_in(&state, input);
    
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
    
    // Output transformation
    state_out(&state, output);
}

// AES-NI encryption of a single block
void AES_Encrypt_Block_NI(__m128i* plain, __m128i* key_schedule, __m128i* cipher) {
    __m128i tmp = _mm_loadu_si128(plain);
    
    tmp = _mm_xor_si128(tmp, key_schedule[0]);
    
    // 9 rounds
    for(int i = 1; i < 10; i++) {
        tmp = _mm_aesenc_si128(tmp, key_schedule[i]);
    }
    
    // Final round
    tmp = _mm_aesenclast_si128(tmp, key_schedule[10]);
    
    _mm_storeu_si128(cipher, tmp);
}

void AES_Encrypt_Serial_CTR(uint8_t* input, const uint8_t* roundKey, uint8_t* output, 
                          int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t counter_block[16];
    uint8_t keystream[16];
    
    for(int i = 0; i < num_blocks; i++) {
        // Prepare counter block for this block
        prepare_ctr_block(initial_ctr, counter_block, i);
        
        // Encrypt counter block to create keystream
        AES_Encrypt_Block(counter_block, roundKey, keystream);
        
        // XOR keystream with input to create output
        for(int j = 0; j < 16; j++) {
            output[i * 16 + j] = input[i * 16 + j] ^ keystream[j];
        }
    }
}

inline __m512i m128i_to_m512i(__m128i src) {
    __m512i result = _mm512_setzero_si512();

    result = _mm512_inserti64x2(result, src, 0);
    result = _mm512_inserti64x2(result, src, 1);
    result = _mm512_inserti64x2(result, src, 2);
    result = _mm512_inserti64x2(result, src, 3);

    return result;
}

// AES-NI parallel encryption
void AES_Encrypt_AESNI_CTR(uint8_t* input, __m128i* key_schedule, uint8_t* output, 
                          int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t counter_block[16];
    __m512i counter_block_vec;
    __m512i keystream;
    __m512i input_block;
    
    for(int i = 0; i < num_blocks; i+=4) {
        __m128i temp_sub_counter_block;
        // Prepare counter block
        prepare_ctr_block(initial_ctr, counter_block, i+0);
        temp_sub_counter_block = _mm_loadu_si128((__m128i*)counter_block);
        counter_block_vec = _mm512_inserti64x2(coun
        ter_block_vec, temp_sub_counter_block, 0);

        prepare_ctr_block(initial_ctr, counter_block, i+1);
        temp_sub_counter_block = _mm_loadu_si128((__m128i*)counter_block);
        counter_block_vec = _mm512_inserti64x2(counter_block_vec, temp_sub_counter_block, 1);

        prepare_ctr_block(initial_ctr, counter_block, i+2);
        temp_sub_counter_block = _mm_loadu_si128((__m128i*)counter_block);
        counter_block_vec = _mm512_inserti64x2(counter_block_vec, temp_sub_counter_block, 2);

        prepare_ctr_block(initial_ctr, counter_block, i+3);
        temp_sub_counter_block = _mm_loadu_si128((__m128i*)counter_block);
        counter_block_vec = _mm512_inserti64x2(counter_block_vec, temp_sub_counter_block, 3);

        __m512i key_schedule512 = m128i_to_m512i(key_schedule[0]);
        // Encrypt counter block using AES-NI
        counter_block_vec = _mm512_xor_si512(counter_block_vec, key_schedule512);
        for(int j = 1; j < 10; j++) {
            key_schedule512 = m128i_to_m512i(key_schedule[j]);
            counter_block_vec = _mm512_aesenc_epi128(counter_block_vec, key_schedule512);
        }
        key_schedule512 = m128i_to_m512i(key_schedule[10]);
        keystream = _mm512_aesenclast_epi128(counter_block_vec, key_schedule512);
        
        // XOR with input
        input_block = _mm512_load_si512((__m512i*)(input + i * 16));
        _mm512_storeu_si512((__m128i*)(output + i * 16), 
                        _mm512_xor_si512(input_block, keystream));
    }
}

int main() {
    // Check AES-NI support
    if (!check_aesni_support()) {
        printf("AES-NI is not supported on this CPU!\n");
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
    
    // Aligned memory allocation (aligned to 16-byte boundary for SSE)
    uint8_t *input = (uint8_t*)aligned_alloc(16, NUM_BLOCKS * 16);
    uint8_t *output_serial = (uint8_t*)aligned_alloc(16, NUM_BLOCKS * 16);
    uint8_t *output_aesni = (uint8_t*)aligned_alloc(16, NUM_BLOCKS * 16);
    uint8_t *roundKey = (uint8_t*)aligned_alloc(16, 176);
    __m128i *key_schedule = (__m128i*)aligned_alloc(16, 176);
    
    if (!input || !output_serial || !output_aesni || !roundKey || !key_schedule) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    
    // Initialize input
    for(int i = 0; i < NUM_BLOCKS * 16; i++) {
        input[i] = i & 0xFF;
    }
    
    // Key expansion for both versions
    KeyExpansion(key, roundKey);  // For serial version
    KeyExpansion_AES_NI(key, key_schedule);  // For AES-NI version
    
    // Warm up
    AES_Encrypt_Serial_CTR(input, roundKey, output_serial, 1, &initial_ctr);
    AES_Encrypt_AESNI_CTR(input, key_schedule, output_aesni, 1, &initial_ctr);
    
    // Serial encryption
    clock_t start = clock();
    AES_Encrypt_Serial_CTR(input, roundKey, output_serial, NUM_BLOCKS, &initial_ctr);
    double serial_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    
    // AES-NI encryption
    start = clock();
    KeyExpansion_AES_NI(key, key_schedule);  // For AES-NI version
    AES_Encrypt_AESNI_CTR(input, key_schedule, output_aesni, NUM_BLOCKS, &initial_ctr);
    double aesni_time = (double)(clock() - start) / CLOCKS_PER_SEC;
    
    // Verify results
    printf("Results match: %s\n",
           memcmp(output_serial, output_aesni, NUM_BLOCKS * 16) == 0 ? "Yes" : "No");
    
    // Calculate throughput
    double data_size_gb = (double)(NUM_BLOCKS * BLOCK_SIZE) / (1024 * 1024 * 1024);
    
    printf("Data size: %.2f GB\n", data_size_gb);
    printf("Serial Time: %.4f seconds (%.2f GB/s)\n",
           serial_time, data_size_gb / serial_time);
    printf("AES-NI Time: %.4f seconds (%.2f GB/s)\n",
           aesni_time, data_size_gb / aesni_time);
    printf("Speedup: %.2fx\n", serial_time / aesni_time);
    
    // Print first block comparison
    printf("\nFirst block comparison:\nSerial: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", output_serial[i]);
    }
    printf("\nAES-NI: ");
    for(int i = 0; i < 16; i++) {
        printf("%02x ", output_aesni[i]);
    }
    printf("\n");
    
    // Clean up
    free(input);
    free(output_serial);
    free(output_aesni);
    free(roundKey);
    free(key_schedule);
    
    return 0;
}