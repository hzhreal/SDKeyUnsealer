#include "ps4.h"
#include "socket.h"
#include "sealed_key.h"

#define PORT 9095
#define SERVER_NAME "SDKeyUnsealer"

#define CHKS_LEN 2

int obtain_IP(char *ip_address) {
    int ret = -1;

    SceNetCtlInfo netInfo;
    memset(&netInfo, 0, sizeof(SceNetCtlInfo));
    
    ret = sceNetCtlInit();
    if (ret >= 0) {
        ret = sceNetCtlGetInfo(SCE_NET_CTL_INFO_IP_ADDRESS, &netInfo);

        if (ret >= 0) {
            memcpy(ip_address, netInfo.ip_address, sizeof(netInfo.ip_address));
            sceNetCtlTerm();
        }
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
    snprintf(chks_str, CHKS_LEN + 1, "%02x", sum);
}

int _main(struct thread *td) {
    int server_socket = -1;
    char ip_address[SCE_NET_CTL_IPV4_ADDR_STR_LEN] = {0};
    struct sockaddr_in sk;

    UNUSED(td);

    // initialize
    initKernel();
    initLibc();
    initNetwork();

    jailbreak();
    initSysUtil();

    memset(&sk, 0, sizeof(struct sockaddr_in));

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
    if (bindSocket(server_socket, (struct sockaddr *)&sk, sizeof(struct sockaddr_in)) < 0) {
        printf_notification("Could not bind socket.");
        goto exit;
    }

    // put socket in listening mode
    if (listenSocket(server_socket, 5) < 0) {
        printf_notification("Failed to put socket in listening mode.");
        goto exit;
    }

    printf_notification("%s: %s %d", SERVER_NAME, ip_address, PORT);
   
    // handle incoming connections, FOREVER
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_socket;
        int bytes_received;
        uint8_t buffer[ENC_KEY_LEN + CHKS_LEN];
        uint8_t out[DEC_KEY_LEN + CHKS_LEN];
        char chks[CHKS_LEN + 1];

        PfsSKKey *sealed_key = (PfsSKKey *)malloc(sizeof(PfsSKKey));
        if (!sealed_key) {
            printf_notification("Memory allocation error.");
            break;
        }

        memset(buffer, 0, sizeof(buffer));
        memset(sealed_key, 0, sizeof(PfsSKKey));

        // accept client connection
        client_socket = sceNetAccept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket <= 0) {
            continue;
        }

        // receive data from client
        bytes_received = sceNetRecv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_received < 0) {
            goto iterate;
        }

        // checksum
        calc_chks(buffer, ENC_KEY_LEN, chks);
        if (memcmp(buffer + ENC_KEY_LEN, chks, CHKS_LEN) != 0) {
            char msg[] = "Invalid checksum or data length.";
            SckSend(client_socket, msg, sizeof(msg) - 1);
            goto iterate;
        }

        memcpy(sealed_key, buffer, ENC_KEY_LEN);

        // check if if key is valid
        if (validateSealedKey(sealed_key) != 0) {
            char msg[] = "Invalid sealed key.";
            SckSend(client_socket, msg, sizeof(msg) - 1);
            goto iterate;
        }

        // finally, decrypt key
        if (decryptSealedKey(sealed_key) == -1) {
            char msg[] = "Failed to decrypt key.";
            SckSend(client_socket, msg, sizeof(msg) - 1);
            goto iterate;
        }

        // send back decrypted key + checksum to client, SUCCESS
        calc_chks(sealed_key->entry.DEC_KEY, DEC_KEY_LEN, chks);
        memcpy(out, sealed_key->entry.DEC_KEY, DEC_KEY_LEN);
        memcpy(out + DEC_KEY_LEN, chks, CHKS_LEN);
        SckSend(client_socket, (char *)out, sizeof(out));

        iterate:
            if (sealed_key) {
                free(sealed_key);
            }
            SckClose(client_socket);
            continue;
    }

    exit:
        if (server_socket >= 0) {
            SckClose(server_socket);
        }
        printf_notification("Exiting...");
        return 0;
}