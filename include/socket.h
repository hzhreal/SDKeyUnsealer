#ifndef SOCKET_H
#define SOCKET_H

#include "ps4.h"

int createSocket(struct sockaddr_in **sk, const char *name, const char host[SCE_NET_CTL_IPV4_ADDR_STR_LEN], uint16_t port);
int bindSocket(int sockfd, struct sockaddr *addr, int addrlen);
int listenSocket(int sockfd, int backlog);

#endif // SOCKET_H