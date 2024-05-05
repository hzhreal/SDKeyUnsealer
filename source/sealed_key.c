#include "sealed_key.h"

int decryptSealedKey(uint8_t *sealedKey, uint8_t *decryptedSealedKey) {
    uint8_t dummy[0x10];
    int fd;
    uint8_t data[ENC_KEY_LEN + DEC_KEY_LEN] = {0};
    memset(data, 0, sizeof(data));

    UNUSED(dummy);

    if ((fd = open("/dev/sbl_srv", 0, O_RDWR)) == -1) {
        return -1;
    }

    memcpy(data, sealedKey, ENC_KEY_LEN);

    if (ioctl(fd, 0xc0845302, data) == -1) {
        close(fd);
        return -1;
    }

    memcpy(decryptedSealedKey, &data[ENC_KEY_LEN], DEC_KEY_LEN);

    close(fd);
    return 0;
}