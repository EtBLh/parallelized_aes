#include <stdio.h>
#include <stdint.h>
#include <string.h>

// The number of columns (32-bit words) comprising the state
#define Nb 4
// The number of 32-bit words in the key
#define Nk 4
// The number of rounds
#define Nr 10

// State array and key
typedef uint8_t state_t[4][4];
static uint8_t RoundKey[240];

// The S-box table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    // ... (truncated for brevity - in practice you would include all 256 values)
};

// The Rcon table
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Key Expansion function
void KeyExpansion(uint8_t* key) {
    uint8_t temp[4], k;
    
    // The first round key is the key itself
    for(int i = 0; i < Nk * 4; i++)
        RoundKey[i] = key[i];
    
    // All other round keys are derived from previous round keys
    int i = Nk;
    while(i < Nb * (Nr + 1)) {
        for(int j = 0; j < 4; j++)
            temp[j] = RoundKey[(i-1) * 4 + j];
        
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
            RoundKey[i * 4 + j] = RoundKey[(i-Nk) * 4 + j] ^ temp[j];
        }
        i++;
    }
}

// AddRoundKey transformation
void AddRoundKey(uint8_t round, state_t* state) {
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
}

// SubBytes transformation
void SubBytes(state_t* state) {
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            (*state)[i][j] = sbox[(*state)[i][j]];
}

// ShiftRows transformation
void ShiftRows(state_t* state) {
    uint8_t temp;
    
    // Rotate first row 1 column to left
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
    temp = (*state)[3][3];
    (*state)[3][3] = (*state)[3][2];
    (*state)[3][2] = (*state)[3][1];
    (*state)[3][1] = (*state)[3][0];
    (*state)[3][0] = temp;
}

// MixColumns transformation
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

// AES encryption function
void AES_Encrypt(uint8_t* input, uint8_t* key, uint8_t* output) {
    state_t* state = (state_t*)input;
    
    // Key expansion
    KeyExpansion(key);
    
    // Initial round
    AddRoundKey(0, state);
    
    // Rounds
    for(uint8_t round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state);
    }
    
    // Final round
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state);
    
    // Copy the state to the output array
    memcpy(output, state, 16);
}

// Example usage
int main() {
    // Example key (128 bits)
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    
    // Example plaintext (128 bits)
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t ciphertext[16];
    
    // Encrypt
    AES_Encrypt(plaintext, key, ciphertext);
    
    // Print results
    printf("Plaintext: ");
    for(int i = 0; i < 16; i++)
        printf("%02x ", plaintext[i]);
    printf("\n");
    
    printf("Key: ");
    for(int i = 0; i < 16; i++)
        printf("%02x ", key[i]);
    printf("\n");
    
    printf("Ciphertext: ");
    for(int i = 0; i < 16; i++)
        printf("%02x ", ciphertext[i]);
    printf("\n");
    
    return 0;
}