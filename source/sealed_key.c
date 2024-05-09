#include "sealed_key.h"

int validateSealedKey(PfsSKKey *key) {
    // compare MAGIC
    if (memcmp(key->entry.MAGIC, SEALED_KEY_MAGIC, sizeof(SEALED_KEY_MAGIC)) != 0) {
        return -1;
    }
    return 0;
}

int decryptSealedKey(PfsSKKey *key) {
    uint8_t dummy[0x10];
    int fd;
    uint8_t data[ENC_KEY_LEN + DEC_KEY_LEN];
    memset(data, 0, sizeof(data));

    UNUSED(dummy);

    if ((fd = open("/dev/sbl_srv", 0, O_RDWR)) == -1) {
        return -1;
    }

    memcpy(data, key, ENC_KEY_LEN);

    if (ioctl(fd, 0xc0845302, data) == -1) {
        close(fd);
        return -1;
    }

    memcpy(key->entry.DEC_KEY, &data[ENC_KEY_LEN], DEC_KEY_LEN);

    close(fd);
    return 0;
}