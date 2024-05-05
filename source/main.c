#include "ps4.h"
#include "socket.h"
#include "sealed_key.h"

#define PORT 9095
#define SERVER_NAME "SDKeyUnsealer"

#define CHKS_LEN 2

int obtain_IP(char *ip_address) {
    int ret = -1;

    SceNetCtlInfo *netInfo = (SceNetCtlInfo *)malloc(sizeof(SceNetCtlInfo));
    if (!netInfo) {
        goto clean;
    }
    memset(netInfo, 0, sizeof(SceNetCtlInfo));
    
    ret = sceNetCtlInit();
    if (ret >= 0) {
        ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, netInfo);

        if (ret >= 0) {
            memcpy(ip_address, netInfo->ip_address, sizeof(netInfo->ip_address));
            sceNetCtlTerm();
        }
    }

    clean:
        if (netInfo) {
            free(netInfo);
        }
        return ret;
}

// get the every byte as int, keep adding the sum to uint8_t 
void calc_chks(uint8_t *data, size_t len, char *chks_str) {
    uint8_t sum = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        sum += data[i];
    }
    sprintf(chks_str, "%02x", sum);
}

int _main(struct thread *td) {
    int server_socket = -1;
    char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN] = {0};
    struct sockaddr_in *sk;

    UNUSED(td);

    // initialize
    initKernel();
    initLibc();
    initNetwork();

    jailbreak();
    initSysUtil();

    // get IP Address of console
    if (obtain_IP(ip_address) < 0) {
        printf_notification("Could not find IP address.");
        goto exit;
    }

    // create the socket descriptor
    if ((server_socket = createSocket(&sk, SERVER_NAME, ip_address, PORT)) < 0) {
        printf_notification("Could not create socket.");
        goto exit;
    }

    // bind the socket
    if (bindSocket(server_socket, (struct sockaddr *)sk, sizeof(struct sockaddr_in)) < 0) {
        printf_notification("Could not bind socket.");
        goto exit;
    }

    // put socket in listening mode
    if (listenSocket(server_socket, 5) < 0) {
        printf_notification("Failed to put socket in listening mode.");
        goto exit;
    }

    printf_notification("SDKeyUnsealer: %s %d", ip_address, PORT);
   
    // handle incoming connections, FOREVER
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket;
        int bytes_received;
        int ret;
        uint8_t buffer[ENC_KEY_LEN + CHKS_LEN];
        uint8_t out[DEC_KEY_LEN + CHKS_LEN];
        uint8_t enc_key[ENC_KEY_LEN];
        uint8_t dec_key[DEC_KEY_LEN];
        char chks[CHKS_LEN + 1];

        memset(buffer, 0, sizeof(buffer));
        memset(enc_key, 0, sizeof(enc_key));
        memset(dec_key, 0, sizeof(dec_key));

        // accept client connection
        client_socket = sceNetAccept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            continue;
        }

        // receive data from client
        bytes_received = sceNetRecv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            SckClose(client_socket);
            continue;
        }

        // checksum
        calc_chks(buffer, ENC_KEY_LEN, chks);
        if (memcmp(buffer + ENC_KEY_LEN, chks, CHKS_LEN) != 0) {
            char msg[] = "Invalid checksum or data length.";
            SckSend(client_socket, msg, sizeof(msg) - 1);
            SckClose(client_socket);
            continue;
        }

        memcpy(enc_key, buffer, ENC_KEY_LEN);
        ret = decryptSealedKey(buffer, dec_key);
        if (ret == -1) {
            char msg[] = "Failed to decrypt key.";
            SckSend(client_socket, msg, sizeof(msg) - 1);
            SckClose(client_socket);
            continue;
        }

        calc_chks(dec_key, DEC_KEY_LEN, chks);
        memcpy(out, dec_key, DEC_KEY_LEN);
        memcpy(out + DEC_KEY_LEN, chks, CHKS_LEN);

        SckSend(client_socket, (char *)out, sizeof(out));
        SckClose(client_socket);
    }

    exit:
        if (server_socket >= 0) {
            SckClose(server_socket);
        }
        printf_notification("Exiting...");
        return 0;
}