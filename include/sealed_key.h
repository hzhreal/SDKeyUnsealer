#ifndef SEALED_KEY_H
#define SEALED_KEY_H

#include "ps4.h"

#define ENC_KEY_LEN 96
#define DEC_KEY_LEN 32

int decryptSealedKey(uint8_t *sealedKey, uint8_t *decryptedSealedKey);

#endif // SEALED_KEY_H