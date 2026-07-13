#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../lib/rabbit.h"

void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  1. Key Generation:\n");
    fprintf(stderr, "     %s -k <key_file_path>\n\n", prog);
    fprintf(stderr, "  2. Encryption / Decryption (with random IV):\n");
    fprintf(stderr, "     cat input | %s -e <key_file_path> > output\n", prog);
    fprintf(stderr, "     cat input | %s -d <key_file_path> > output\n\n", prog);
    fprintf(stderr, "  3. Encryption / Decryption (without IV):\n");
    fprintf(stderr, "     cat input | %s -e -noiv <key_file_path> > output\n", prog);
    fprintf(stderr, "     cat input | %s -d -noiv <key_file_path> > output\n", prog);
}

int generate_key_file(const char *path) {
    csrng rng;
    if (initNumberGenerator(&rng) == -1) {
        perror("RNG initialization failed");
        return 1;
    }

    rabbit_word_t rand_val = randomNumber(&rng);
    size_t key_size = 17 + (rand_val % 17);

    uint8_t *raw_key = malloc(key_size);
    if (!raw_key) {
        perror("Memory allocation failed");
        return 1;
    }

    for (uint8_t i = 0; i < key_size; i++) {
        raw_key[i] = randomByte(&rng);
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("Key file creation failed");
        free(raw_key);
        return 1;
    }

    if (fwrite(raw_key, 1, key_size, f) != key_size) {
        perror("Key file write failed");
        fclose(f);
        free(raw_key);
        return 1;
    }

    fclose(f);
    free(raw_key);
    fprintf(stderr, "Success: Key file saved to %s (%zu bytes)\n", path, key_size);
    return 0;
}

int read_key_file(const char *path, rabbit_word_t key[RABBIT_KEY_WORDS]) {
    uint8_t raw_key[16];
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("Opening key file failed");
        return 1;
    }

    size_t read_bytes = fread(raw_key, 1, 16, f);
    fclose(f);

    if (read_bytes < 16) {
        fprintf(stderr, "Error: Key file is too small (minimum 16 bytes required, read %zu).\n", read_bytes);
        return 1;
    }

    for (uint8_t i = 0; i < RABBIT_KEY_WORDS; ++ i) key[i] = 0;
    for (uint8_t i = 0; i < 16; i++) {
        key[i >> ENCRYPT_SHIFT] |= ((rabbit_word_t)raw_key[i]) << (
            ((sizeof(rabbit_word_t) - 1) - (
                i & (sizeof(rabbit_word_t) - 1)
            )) * 8
        );
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-k") == 0) {
        return generate_key_file(argv[2]);
    }

    int mode = 0;
    int no_iv_flag = 0;
    const char *key_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "-noiv") == 0) {
            no_iv_flag = 1;
        } else {
            key_path = argv[i];
        }
    }

    if (mode == 0 || key_path == NULL) {
        fprintf(stderr, "Error: Invalid arguments.\n");
        print_usage(argv[0]);
        return 1;
    }

    rabbit_word_t key[RABBIT_KEY_WORDS];
    if (read_key_file(key_path, key) != 0) {
        return 1;
    }

    rabbit_word_t iv_val[RABBIT_IV_WORDS];
    rabbit_word_t *iv_ptr = NULL;

    if (!no_iv_flag) {
        if (mode == 1) {
            csrng rng;
            if (initNumberGenerator(&rng) == -1) {
                perror("RNG initialization failed for IV");
                return 1;
            }
            for (uint8_t i = 0; i < RABBIT_IV_WORDS; ++ i){
                iv_val[i] = randomNumber(&rng);
            }
            if (fwrite(&iv_val, 1, 8, stdout) != 8) {
                perror("Failed to write IV to stdout");
                return 1;
            }
            iv_ptr = iv_val;
        } else if (mode == 2) {
            if (fread(&iv_val, 1, 8, stdin) != 8) {
                fprintf(stderr, "Error: Failed to read IV from stdin.\n");
                return 1;
            }
            iv_ptr = iv_val;
        }
    }

    scheduler state;
    initScheduler(&state, key, iv_ptr);
    secure_wipe(key, sizeof(key));
    secure_wipe(iv_val, sizeof(iv_val));

    uint8_t buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
        size_t i = 0;

        while (i + sizeof(rabbit_word_t) <= bytes_read){
            rabbit_word_t block;
            memcpy(&block, buffer + i, sizeof(rabbit_word_t));
            block = encryptWord(&state, block);
            memcpy(buffer + i, &block, sizeof(rabbit_word_t));
            i += sizeof(rabbit_word_t);
        }

        for (; i < bytes_read; i++) {
            buffer[i] = encryptByte(&state, buffer[i]);
        }
        
        size_t bytes_written = fwrite(buffer, 1, bytes_read, stdout);
        if (bytes_written != bytes_read) {
            perror("Write to stdout failed");
            return 1;
        }
    }

    return 0;
}