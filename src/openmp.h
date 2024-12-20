
#ifndef AESNI_H
#define AESNI_H

#include "aes.h"
#include <omp.h>

int  check_aesni_support();

void aesctr_enc_openmp(uint8_t* input, uint8_t* key_schedule, uint8_t* output, int num_blocks, ctr_block_t* initial_ctr);

#endif
