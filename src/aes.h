#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

//----------------------------------constants----------------------------------

#define Nb 4
#define Nk 4
#define Nr 10
#define MB_TO_TEST 1024
#define BLOCK_SIZE 16
#define NUM_BLOCKS ((MB_TO_TEST * 1024 * 1024) / BLOCK_SIZE)
#define NUM_THREADS 8

typedef uint8_t state_t[4][4];
typedef struct {
    uint8_t nonce[8];    // 64-bit nonce
    uint8_t counter[8];  // 64-bit counter
} ctr_block_t;

extern const uint8_t sbox[256];

// The Rcon table
extern const uint8_t Rcon[11];

extern const uint8_t mul2[256];

extern const uint8_t mul3[256];

//----------------------------------common----------------------------------

void prepare_ctr_block(ctr_block_t* base_ctr, uint8_t* counter_block, uint64_t block_idx);
void setup_counter_block(uint8_t* counter_block, const uint8_t* nonce, uint64_t counter_value);
int compare_buffers(uint8_t* buf1, uint8_t* buf2, size_t size);

//----------------------------------serial----------------------------------

void aes_keyexpansion_serial(uint8_t* key, uint8_t* roundKey);
/**
 * input: the address of input blocks
 * roundKey
 */
void aesctr_enc_serial(uint8_t* input, const uint8_t* roundKey, uint8_t* output, int num_blocks, ctr_block_t* initial_ctr);

void aes_enc1block_serial(uint8_t* input, const uint8_t* roundKey, uint8_t* output);
void aesctr_enc1block_serial(uint8_t* counter, uint8_t* input, const uint8_t* roundKey, uint8_t* output);


#endif