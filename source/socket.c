#include "socket.h"

int createSocket(struct sockaddr_in *sk, const char *name, const char host[SCE_NET_CTL_IPV4_ADDR_STR_LEN], uint16_t port) {
    struct in_addr ip_addr;
    int sck;

    sceNetInetPton(AF_INET, host, &ip_addr);
    
    sk->sin_len = sizeof(*sk);
    sk->sin_family = AF_INET;
    sk->sin_addr = ip_addr;
    sk->sin_port = sceNetHtons(port);
    memset(sk->sin_zero, 0, sizeof(sk->sin_zero));
    sck = sceNetSocket(name, AF_INET, SOCK_STREAM, 0);

    return sck;
}

int bindSocket(int sockfd, struct sockaddr *addr, int addrlen) {
    return sceNetBind(sockfd, addr, addrlen);
}

int listenSocket(int sockfd, int backlog) {
    return sceNetListen(sockfd, backlog);
}