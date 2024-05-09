#ifndef SEALED_KEY_H
#define SEALED_KEY_H

#include "ps4.h"

#define ENC_KEY_LEN 0x60
#define DEC_KEY_LEN 0x20

#define SEALED_KEY_MAGIC ((uint8_t[]){ 'p', 'f', 's', 'S', 'K', 'K', 'e', 'y' })

typedef union sealedkey_t {
    struct entries {
        uint8_t MAGIC[8];
        uint8_t VERSION[8];
        uint8_t IV[16];
        uint8_t KEY[DEC_KEY_LEN];
        uint8_t SHA256[32];
        uint8_t DEC_KEY[DEC_KEY_LEN];
    } entry;
    uint8_t data[sizeof(struct entries)];
} PfsSKKey;

int validateSealedKey(PfsSKKey *key);
int decryptSealedKey(PfsSKKey *key);

#endif // SEALED_KEY_H