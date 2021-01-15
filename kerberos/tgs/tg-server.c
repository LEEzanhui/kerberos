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

unsigned char TGSKEY[] = "87654321";
unsigned char SSKEY[] = "76543210";
unsigned char cliSsKey[] = "98765432";
unsigned char cliTgsKey[BUFSIZE];
unsigned char clientID[BUFSIZE];
unsigned char serviceID[BUFSIZE];

int responseReqC(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen);
int responseReqD(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen);
unsigned char *getCliSsKey();
unsigned char *pkgMsgE(char *msgB, unsigned char *cliTgsKey,
                       struct sockaddr *cliAddr);

int main(int argc, char const *argv[]) {
    printf("TgsKey: %s\n", TGSKEY);
    printf("SsKey: %s\n", SSKEY);
    printf("cliSsKey: %s\n\n", cliSsKey);

    int listenfd = createServSocket(TGSPORT);

    printf("======waiting for client's request======\n");
    while (1) {
        struct sockaddr cliAddr;
        socklen_t addrLen;
        int connfd = accept(listenfd, &cliAddr, &addrLen);
        if (connfd == -1) {
            fprintf(stderr, "accept error: %s", strerror(errno));
            continue;
        }

        unsigned char msgC[BUFSIZE];
        int n = recv(connfd, msgC, BUFSIZE - 1, 0);
        msgC[n] = '\0';
        if (n > 0) responseReqC(msgC, n, connfd, cliAddr, addrLen);

        // connfd = accept(listenfd, &cliAddr, &addrLen);
        // if (connfd == -1) {
        //     fprintf(stderr, "accept error: %s", strerror(errno));
        //     continue;
        // }
        unsigned char msgD[BUFSIZE];
        n = recv(connfd, msgD, BUFSIZE - 1, 0);
        msgD[n] = '\0';
        if (n > 0) responseReqD(msgD, n, connfd, cliAddr, addrLen);

        close(connfd);

        printf("Success!\n");
    }

    close(listenfd);
    return 0;
}

int responseReqC(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen) {
    printf("server: receive request from client\n");
    printf("\nreceive msgC\n");

    unsigned char msgB[BUFSIZE], leftB[BUFSIZE];

    strcpy(leftB, buf + 6);
    strncpy(serviceID, buf, 6);
    serviceID[6] = 0;

    generateSubKey(TGSKEY);
    decryption(leftB, msgB);

    printf("msgC: ");
    for (int i = 0; buf[i] != '\0'; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    // printf("msgC: %s\n", buf);
    // printf("leftB: %s\n", leftB);
    printf("serviceID: %s\n", serviceID);
    printf("TGSKEY: %s\n", TGSKEY);
    printf("msgB after dec: %s\n", msgB);

    unsigned char timebuffer[50];
    memset(timebuffer, 0, sizeof(timebuffer));
    strncpy(timebuffer, msgB + 22, 10);
    timebuffer[10] = 0;
    printf("msgB validity: %s\n", timebuffer);
    time_t start = atol(timebuffer);
    time_t end;
    time(&end);
    printf("nowtime: %ld\n", end);
    double cost = difftime(start, end);
    if (cost <= 0) {
        printf("\nRefuse: Validate is out of date.\n");
        return 0;
    }

    strcpy(cliTgsKey, msgB + 32);

    return 0;
}

int responseReqD(unsigned char *buf, int n, int connfd, struct sockaddr cliAddr,
                 socklen_t addrLen) {
    // printf("server: receive request from client\n");
    printf("\nreceive msgD\n");

    unsigned char msgD[BUFSIZE], pkgMsgD[BUFSIZE];
    generateSubKey(cliTgsKey);

    decryption(buf, msgD);

    // printf("%ld", strlen(buf));

    printf("msgD: ");
    for (int i = 0; buf[i] != '\0'; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    // printf("buf: %s\n", buf);
    printf("cliTgsKEY: %s\n", cliTgsKey);
    printf("msgD after dec: %s\n", msgD);

    unsigned char timestamp[BUFSIZE];
    strncpy(clientID, msgD, 8);
    clientID[8] = 0;
    strncpy(timestamp, msgD + 8, 10);
    timestamp[10] = 0;
    printf("clientID: %s\n", clientID);
    printf("timestamp: %s\n", timestamp);

    printf("\nsend msgE\n");
    unsigned char msgE[BUFSIZE], enE[BUFSIZE], sendE[BUFSIZE];
    pkgMsgE(msgE, getCliSsKey(), &cliAddr);
    generateSubKey(SSKEY);
    encryption(msgE, enE);

    strcpy(sendE, serviceID);
    strcat(sendE, enE);

    printf("ST before enc: %s\n", msgE);
    // printf("msgE: %s\n", sendE);
    printf("msgE: ");
    for (int i = 0; sendE[i] != '\0'; i++) {
        printf("%02x", sendE[i]);
    }
    printf("\n");

    int len;
    len = send(connfd, sendE, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nsend msgF\n");

    unsigned char msgF[BUFSIZE];
    generateSubKey(cliTgsKey);
    encryption(getCliSsKey(), msgF);

    len = send(connfd, msgF, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("cliSsKey: %s\n", getCliSsKey());

    return 0;
}

unsigned char *getCliSsKey() { return cliSsKey; }

unsigned char *pkgMsgE(char *msgE, unsigned char *cliSsKey,
                       struct sockaddr *cliAddr) {
    strcpy(msgE, clientID);
    strcat(msgE, cliAddr->sa_data);
    for (int i = 0; i < 14 - strlen(cliAddr->sa_data); i++) {
        strcat(msgE, "0");
    }

    time_t validate;
    time(&validate);
    validate += 10 * 60;
    unsigned char timebuffer[50];
    sprintf(timebuffer, "%ld", validate);
    strcat(msgE, timebuffer);

    printf("msgE validity: %s\n", timebuffer);

    strcat(msgE, cliSsKey);
    return msgE;
}
