#ifndef RABBIT_UNI_IMPL_H
#define RABBIT_UNI_IMPL_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define LS16B 65535U
#define LS32B 4294967295U


#ifdef RABBIT_32BIT
    typedef uint32_t rabbit_word_t;
    #define RABBIT_S_LEN 4
    #define RABBIT_KEY_WORDS 4
    #define RABBIT_IV_WORDS 2
    #define ENCRYPT_SHIFT 2
#else
    typedef uint64_t rabbit_word_t;
    #define RABBIT_S_LEN 2
    #define RABBIT_KEY_WORDS 2
    #define RABBIT_IV_WORDS 1
    #define ENCRYPT_SHIFT 3
#endif

//Struct that contains variables used in gamma generation and stream encryption.
typedef struct __scheduler_t {
    uint32_t X[8];
    uint32_t C[8];
    rabbit_word_t S[RABBIT_S_LEN];  
    uint8_t carry;   
    uint8_t pos;
} scheduler;

// function with volatile memory access. Used to wipe key from memory.
static inline void secure_wipe(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

// Inits passed scheduler struct, using key and IV array. Pass NULL point for IV to not use IV. 
void initScheduler(scheduler * state, const rabbit_word_t * key, const rabbit_word_t * iv);

// Generates new S-block.
void extractSBlock(scheduler * state);

uint8_t encryptByte(scheduler * state, uint8_t byte);

// Encrypts whole word (size of word is based on biggest available uint).
rabbit_word_t encryptWord(scheduler * state, rabbit_word_t block);

// Wraps Rabbit scheduler to be used as random number generator.
typedef struct csrng_t{
    scheduler state;
} csrng;

int initNumberGenerator(csrng * rng);
rabbit_word_t randomNumber(csrng * rng);
uint8_t randomByte(csrng * rng);

#endif
