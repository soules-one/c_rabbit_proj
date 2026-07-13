#include "rabbit.h"

#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
#elif defined(EPS_PLATFORM)
    #include <esp_random.h>
#else
    #include <sys/random.h>
    #include <unistd.h> 
#endif

#define ROTL32(a, b) (((uint32_t)(a) << (b)) | ((uint32_t)(a) >> (32 - (b))))


static inline uint32_t g(uint32_t u, uint32_t v) {
    // Removed to allow better compiler optimisation
    /* #ifdef RABBIT_32BIT
    const uint32_t s  = u + v; 
    const uint32_t a0 = s & LS16B;
    const uint32_t a1 = s >> 16;
    const uint32_t p0 = a0 * a0;
    const uint32_t p1 = a0 * a1;
    const uint32_t p2 = a1 * a1;
    const uint32_t lo = p0 + (p1 << 17);
    return p2 + (p1 >> 15) + (lo < p0) ^ lo;
    */
    //#else
    const uint64_t sq = (uint64_t)(u + v) * (u + v);
    return (uint32_t)(sq ^ (sq >> 32));
    //#endif
}

void counterUpdate(scheduler * state) {
    const uint32_t A[8] = {
        0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
        0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
    };
    for (uint8_t i = 0; i < 8; ++i) {
        rabbit_word_t oldC = state->C[i];
        state->C[i] = oldC + A[i] + state->carry;
        state->carry = state->C[i] <= oldC ? 1 : 0;
    }
}

void nextState(scheduler * state) {
    uint32_t G[8];
    for (uint8_t i = 0; i < 8; ++i) {
        G[i] = g(state->X[i], state->C[i]);
    }
    state->X[0] = (uint32_t)(G[0] + ROTL32(G[7], 16) + ROTL32(G[6], 16));
    state->X[1] = (uint32_t)(G[1] + ROTL32(G[0], 8) + G[7]);
    state->X[2] = (uint32_t)(G[2] + ROTL32(G[1], 16) + ROTL32(G[0], 16));
    state->X[3] = (uint32_t)(G[3] + ROTL32(G[2], 8) + G[1]);
    state->X[4] = (uint32_t)(G[4] + ROTL32(G[3], 16) + ROTL32(G[2], 16));
    state->X[5] = (uint32_t)(G[5] + ROTL32(G[4], 8) + G[3]);
    state->X[6] = (uint32_t)(G[6] + ROTL32(G[5], 16) + ROTL32(G[4], 16));
    state->X[7] = (uint32_t)(G[7] + ROTL32(G[6], 8) + G[5]);
}

void initScheduler(scheduler * state, const rabbit_word_t * key, const rabbit_word_t * iv) {
    uint16_t K[8];

    state->carry = 0;
    state->pos = 16; 

    for (uint8_t i = 0; i < 8; ++i) {
        #ifdef RABBIT_32BIT
        uint8_t word_idx = 3 - (i >> 1);
        uint8_t shift = (i & 1) * 16;
        #else
        uint8_t word_idx = 1 - (i >> 2);
        uint8_t shift = (i & 3) * 16;
        #endif
        K[i] = (key[word_idx] >> shift) & LS16B;
    }

    for (uint8_t i = 0; i < 8; ++i) {
        if ((i & 1) == 0) {
            state->X[i] = ((uint32_t)K[(i + 1) & 7] << 16) | K[i];
            state->C[i] = ((uint32_t)K[(i + 4) & 7] << 16) | K[(i + 5) & 7];
        } else {
            state->X[i] = ((uint32_t)K[(i + 5) & 7] << 16) | K[(i + 4) & 7];
            state->C[i] = ((uint32_t)K[i] << 16) | K[(i + 1) & 7];
        }
    }

    for (uint8_t i = 0; i < 4; ++i) {
        counterUpdate(state);
        nextState(state);
    }

    for (uint8_t i = 0; i < 8; ++i) {
        state->C[i] ^= state->X[(i + 4) & 7];
    }

    if (iv != NULL) {
        #ifdef RABBIT_32BIT
        uint32_t iv0 = (uint32_t)(iv[1]);
        uint32_t iv1 = (uint32_t)(iv[0]);
        #else
        uint32_t iv0 = (uint32_t)(iv[0] & 0xFFFFFFFF);
        uint32_t iv1 = (uint32_t)(iv[0] >> 32);
        #endif

        uint16_t ivw[4] = {
            (uint16_t)(iv0 & 0xFFFF), (uint16_t)(iv0 >> 16),
            (uint16_t)(iv1 & 0xFFFF), (uint16_t)(iv1 >> 16)
        };
        
        uint32_t ivo1 = ((uint32_t)ivw[3] << 16) | ivw[1];
        uint32_t ivo3 = ((uint32_t)ivw[2] << 16) | ivw[0];
        
        state->C[0] ^= iv0;
        state->C[1] ^= ivo1;
        state->C[2] ^= iv1;
        state->C[3] ^= ivo3;
        state->C[4] ^= iv0;
        state->C[5] ^= ivo1;
        state->C[6] ^= iv1;
        state->C[7] ^= ivo3;
        
        for (uint8_t i = 0; i < 4; ++i) {
            counterUpdate(state);
            nextState(state);
        }
        secure_wipe(ivw, sizeof(ivw));
    }
    secure_wipe(K, sizeof(K));
}

void extractSBlock(scheduler * state) {
    counterUpdate(state);
    nextState(state);

    #ifdef RABBIT_32BIT
    state->S[3]  = (uint32_t)((state->X[0] & 0xFFFF) ^ (state->X[5] >> 16));
    state->S[3] |= (uint32_t)((state->X[0] >> 16) ^ (state->X[3] & 0xFFFF)) << 16;
    state->S[2] = (uint32_t)((state->X[2] & 0xFFFF) ^ (state->X[7] >> 16));
    state->S[2] |= (uint32_t)((state->X[2] >> 16) ^ (state->X[5] & 0xFFFF)) << 16;

    state->S[1]  = (uint32_t)((state->X[4] & 0xFFFF) ^ (state->X[1] >> 16));
    state->S[1] |= (uint32_t)((state->X[4] >> 16) ^ (state->X[7] & 0xFFFF)) << 16;
    state->S[0] = (uint32_t)((state->X[6] & 0xFFFF) ^ (state->X[3] >> 16));
    state->S[0] |= (uint32_t)((state->X[6] >> 16) ^ (state->X[1] & 0xFFFF)) << 16;
    #else

    state->S[1]  = (uint64_t)((state->X[0] & 0xFFFF) ^ (state->X[5] >> 16));
    state->S[1] |= (uint64_t)((state->X[0] >> 16) ^ (state->X[3] & 0xFFFF)) << 16;
    state->S[1] |= (uint64_t)((state->X[2] & 0xFFFF) ^ (state->X[7] >> 16)) << 32;
    state->S[1] |= (uint64_t)((state->X[2] >> 16) ^ (state->X[5] & 0xFFFF)) << 48;

    state->S[0]  = (uint64_t)((state->X[4] & 0xFFFF) ^ (state->X[1] >> 16));
    state->S[0] |= (uint64_t)((state->X[4] >> 16) ^ (state->X[7] & 0xFFFF)) << 16;
    state->S[0] |= (uint64_t)((state->X[6] & 0xFFFF) ^ (state->X[3] >> 16)) << 32;
    state->S[0] |= (uint64_t)((state->X[6] >> 16) ^ (state->X[1] & 0xFFFF)) << 48;
    #endif
}

uint8_t encryptByte(scheduler * state, uint8_t byte) {
    if (state->pos >= 16) {
        extractSBlock(state);
        state->pos = 0;
    }
    uint8_t keystream_byte;
    keystream_byte = (state->S[RABBIT_S_LEN - 1 - (state->pos >> ENCRYPT_SHIFT)]
                    >> (((state->pos & (sizeof(rabbit_word_t) - 1)) * 8))) & 0xFF;
    
    state->pos++;
    return byte ^ keystream_byte;
}

rabbit_word_t encryptWord(scheduler * state, rabbit_word_t block) {
    rabbit_word_t keystream = 0;

    if (state->pos >= 16){
        extractSBlock(state);
        state->pos = 0;
    }

    if ((state->pos & (sizeof(rabbit_word_t) - 1)) == 0) {
        keystream = state->S[RABBIT_S_LEN - 1 - (state->pos >> (ENCRYPT_SHIFT))];
        state->pos += sizeof(rabbit_word_t);
        return block ^ keystream;
    } 
    
    rabbit_word_t result = 0;
    for(size_t i = 0; i < sizeof(rabbit_word_t); ++i) {
        uint8_t plain_byte = (block >> (i * 8)) & 0xFF;
        uint8_t cipher_byte = encryptByte(state, plain_byte);
        result |= ((rabbit_word_t)cipher_byte << (i * 8));
    }
    return result;
}

int initNumberGenerator(csrng * rng) {
    rabbit_word_t key[RABBIT_KEY_WORDS];
    ssize_t err = getrandom(key, 16, 0);
    if (err == -1) {
        return err;
    }
    initScheduler(&(rng->state), key, NULL);
    return err;
}

rabbit_word_t randomNumber(csrng * rng) {
    return encryptWord(&(rng->state), 0);
}

uint8_t randomByte(csrng * rng){
    return encryptByte(&(rng->state), 0);
}