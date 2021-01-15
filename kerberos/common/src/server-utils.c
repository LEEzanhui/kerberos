#include "server-utils.h"

#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

int createServSocket(int port) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        fprintf(stderr, "create socket error: %s\n", strerror(errno));
        exit(errno);
    }

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(port);

    int res;
    res = bind(listenfd, (struct sockaddr *)&servAddr, sizeof(servAddr));
    if (res < 0) {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        exit(errno);
    }

    res = listen(listenfd, 10);
    if (res < 0) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        exit(errno);
    }
    return listenfd;
}
