#ifndef AESNI_H
#define AESNI_H

#include "aes.h"

#include <wmmintrin.h>  // AES-NI intrinsics
#include <cpuid.h>      // for checking AES-NI support

int  check_aesni_support();

void aes_keyexpansion_aesni(uint8_t* key, __m128i* key_schedule);

void aesctr_enc_aesni(uint8_t* input, __m128i* key_schedule, uint8_t* output, int num_blocks, ctr_block_t* initial_ctr);

#endif