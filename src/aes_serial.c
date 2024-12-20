#include "aes.h"

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

void aes_keyexpansion_serial(uint8_t* key, uint8_t* roundKey) {
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
void aesctr_enc1block_serial(uint8_t* input, const uint8_t* roundKey, uint8_t* output) {
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

void aesctr_enc_serial(uint8_t* input, const uint8_t* roundKey, uint8_t* output, 
                          int num_blocks, ctr_block_t* initial_ctr) {
    uint8_t counter_block[16];
    uint8_t keystream[16];
    
    for(int i = 0; i < num_blocks; i++) {
        // Prepare counter block for this block
        prepare_ctr_block(initial_ctr, counter_block, i);
        
        // Encrypt counter block to create keystream
        aesctr_enc1block_serial(counter_block, roundKey, keystream);
        
        // XOR keystream with input to create output
        for(int j = 0; j < 16; j++) {
            output[i * 16 + j] = input[i * 16 + j] ^ keystream[j];
        }
    }
}