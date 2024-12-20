#include <wmmintrin.h>  // AES-NI intrinsics
#include <cpuid.h>      // for checking AES-NI support

#include "aesni.h"

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

// AES-NI version of key expansion
void aes_keyexpansion_aesni(uint8_t* userkey, __m128i* key_schedule) {
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

// AES-NI parallel encryption
void aesctr_enc_aesni(uint8_t* input, __m128i* key_schedule, uint8_t* output, 
                          int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t counter_block[16];
    __m128i counter_block_vec;
    __m128i keystream;
    __m128i input_block;
    
    for(int i = 0; i < num_blocks; i++) {
        // Prepare counter block
        prepare_ctr_block(initial_ctr, counter_block, i);
        
        // Load counter block into vector
        counter_block_vec = _mm_loadu_si128((__m128i*)counter_block);
        
        // Encrypt counter block using AES-NI
        counter_block_vec = _mm_xor_si128(counter_block_vec, key_schedule[0]);
        for(int j = 1; j < 10; j++) {
            counter_block_vec = _mm_aesenc_si128(counter_block_vec, key_schedule[j]);
        }
        keystream = _mm_aesenclast_si128(counter_block_vec, key_schedule[10]);
        
        // XOR with input
        input_block = _mm_loadu_si128((__m128i*)(input + i * 16));
        _mm_storeu_si128((__m128i*)(output + i * 16), 
                        _mm_xor_si128(input_block, keystream));
    }
}