#include <errno.h>
#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "des.h"
#include "server-utils.h"
#include "utils.h"

#define BUFSIZE 1024

unsigned char SSKEY[] = "76543210";
unsigned char cliSsKey[BUFSIZE];
unsigned char clientID[BUFSIZE];

int responseReqE(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen);
int responseReqG(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen);

unsigned char *pkgMsgH(unsigned char *msgH, unsigned char *timestamp);

int main(int argc, char const *argv[]) {
    printf("SsKey: %s\n\n", SSKEY);

    int listenfd = createServSocket(SSPORT);

    printf("======waiting for client's request======\n");
    while (1) {
        struct sockaddr cliAddr;
        socklen_t addrLen;
        int connfd = accept(listenfd, &cliAddr, &addrLen);
        if (connfd == -1) {
            fprintf(stderr, "accept error: %s", strerror(errno));
            continue;
        }
        unsigned char msgE[BUFSIZE];
        int n = recv(connfd, msgE, BUFSIZE - 1, 0);
        msgE[n] = '\0';
        if (n > 0) responseReqE(msgE, n, connfd, cliAddr, addrLen);

        // connfd = accept(listenfd, &cliAddr, &addrLen);
        // if (connfd == -1) {
        //     fprintf(stderr, "accept error: %s", strerror(errno));
        //     continue;
        // }
        unsigned char msgG[BUFSIZE];
        n = recv(connfd, msgG, BUFSIZE - 1, 0);
        msgG[n] = '\0';
        if (n > 0) responseReqG(msgG, n, connfd, cliAddr, addrLen);

        close(connfd);

        printf("Success!\n");
    }

    close(listenfd);
    return 0;
}

int responseReqE(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen) {
    printf("server: receive request from client\n");
    printf("\nreceive msgE\n");

    unsigned char st[BUFSIZE], msgE[BUFSIZE];
    strcpy(st, buf + 6);
    generateSubKey(SSKEY);

    decryption(st, msgE);

    // printf("%ld", strlen(buf));

    printf("msgE: ");
    for (int i = 0; buf[i] != '\0'; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    // printf("msgE: %s\n", buf);
    // printf("st: %s\n", st);
    printf("SSKEY: %s\n", SSKEY);
    printf("ST after dec: %s\n", msgE);

    unsigned char timebuffer[50];
    memset(timebuffer, 0, sizeof(timebuffer));
    strncpy(timebuffer, msgE + 22, 10);
    timebuffer[10] = 0;
    printf("ST validity: %s\n", timebuffer);
    time_t start = atol(timebuffer);
    time_t end;
    time(&end);
    printf("nowtime: %ld\n", end);
    double cost = difftime(start, end);
    if (cost < 0) {
        printf("\nRefuse: Validate is out of date.\n");
        return 0;
    }

    strcpy(cliSsKey, msgE + 32);

    printf("cliSsKey: %s\n", cliSsKey);

    return 0;
}

int responseReqG(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen) {
    printf("\nreceive msgG\n");

    unsigned char msgG[BUFSIZE], pkgMsgD[BUFSIZE];
    generateSubKey(cliSsKey);

    decryption(buf, msgG);

    // printf("%ld", strlen(buf));

    printf("msgG: ");
    for (int i = 0; buf[i] != '\0'; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    // printf("buf: %s\n", buf);
    printf("cliSsKey: %s\n", cliSsKey);
    printf("msgG after dec: %s\n", msgG);

    unsigned char timestamp[50];
    strncpy(clientID, msgG, 8);
    clientID[8] = 0;
    strcpy(timestamp, msgG + 8);

    printf("clientID: %s\n", clientID);
    printf("msgG timestamp: %s\n", timestamp);

    printf("\nsend msgH\n");

    unsigned char msgH[BUFSIZE], sendH[BUFSIZE];
    pkgMsgH(msgH, timestamp);
    generateSubKey(cliSsKey);
    encryption(msgH, sendH);

    printf("msgH before enc: %s\n", msgH);

    int len;
    len = send(connfd, sendH, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    return 0;
}

unsigned char *pkgMsgH(unsigned char *msgH, unsigned char *timestamp) {
    strcpy(msgH, clientID);

    unsigned char timebuffer[50];
    memset(timebuffer, 0, sizeof(timebuffer));
    strncpy(timebuffer, timestamp, 10);
    timebuffer[10] = 0;

    printf("msgG timestamp: %s\n", timebuffer);

    time_t start = atol(timebuffer);
    start++;
    memset(timebuffer, 0, sizeof(timebuffer));
    sprintf(timebuffer, "%ld", start);
    strcat(msgH, timebuffer);

    printf("msgH timestamp: %s\n", timebuffer);

    return msgH;
}
