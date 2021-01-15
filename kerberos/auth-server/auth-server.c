#include <errno.h>
#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "des.h"
#include "server-utils.h"
#include "utils.h"

#define BUFSIZE 1024

unsigned char TGSKEY[] = "87654321";
unsigned char clientKey[] = "12345678";
unsigned char cliTgsKey[] = "23456789";

bool isValidUsername(const char *username);
int responseReq(const char *buf, int n, int connfd, struct sockaddr cliAddr,
                socklen_t addrLen);
unsigned char *getCliKey(const char *username);
unsigned char *getCliTgsKey();
unsigned char *pkgMsgB(char *msgB, unsigned char *cliTgsKey,
                       struct sockaddr *cliAddr, unsigned char *username);

int main(int argc, char const *argv[]) {
    printf("TgsKey: %s\n", TGSKEY);
    printf("clientKey: %s\n", clientKey);
    printf("cliTgsKey: %s\n\n", cliTgsKey);

    int listenfd = createServSocket(ASPORT);

    printf("======waiting for client's request======\n");
    while (1) {
        struct sockaddr cliAddr;
        socklen_t addrLen;
        int connfd = accept(listenfd, &cliAddr, &addrLen);
        if (connfd == -1) {
            fprintf(stderr, "accept error: %s", strerror(errno));
            continue;
        }
        char buf[BUFSIZE];
        int n = recv(connfd, buf, BUFSIZE - 1, 0);
        buf[n] = 0;
        if (n > 0) responseReq(buf, n, connfd, cliAddr, addrLen);
        close(connfd);

        printf("Success!\n");
    }

    close(listenfd);
    return 0;
}

int responseReq(const char *buf, int n, int connfd, struct sockaddr cliAddr,
                socklen_t addrLen) {
    char username[n + 1];
    memcpy(username, buf, n);
    username[n] = '\0';
    printf("server: receive request from client (%s)\n", buf);
    if (isValidUsername(username)) {
        unsigned char *cliKey = getCliKey(username);
        unsigned char *cliTgsKey = getCliTgsKey();

        printf("\nsend msgA\n");

        unsigned char msgA[BUFSIZE];
        for (int i = 0; i < BUFSIZE; i++) {
            msgA[i] = '\0';
        }

        generateSubKey(cliKey);
        // encryptionMsg(cliTgsKey, msgA);
        encryption(cliTgsKey, msgA);

        printf("cliTgsKey: %s\n", cliTgsKey);
        // printf("len: %ld\n", strlen(msgA));
        // printf("msgA: %s\n", msgA);

        printf("msgA: ");
        for (int i = 0; msgA[i] != '\0'; i++) {
            printf("%02x", msgA[i]);
        }
        printf("\n");

        int len;
        len = send(connfd, msgA, BUFSIZE - 1, 0);
        if (len < 0) {
            fprintf(stderr, "send error: %s\n", strerror(errno));
            return errno;
        }

        printf("\nsend msgB\n");
        unsigned char msgB[BUFSIZE], buf[BUFSIZE];
        generateSubKey(TGSKEY);
        pkgMsgB(buf, cliTgsKey, &cliAddr, username);
        // encryptionMsg(pkgMsgB(buf, cliTgsKey, &cliAddr, username), msgB);
        encryption(buf, msgB);

        // unsigned char temp[BUFSIZE];
        // decryptionMsg(msgB, temp);

        // printf("msgB: %s\n", msgB);
        printf("msgB before enc: %s\n", buf);
        // printf("temp: %s\n", temp);

        printf("msgB: ");
        for (int i = 0; msgB[i] != '\0'; i++) {
            printf("%02x", msgB[i]);
        }
        printf("\n");

        len = send(connfd, msgB, BUFSIZE - 1, 0);
        if (len < 0) {
            fprintf(stderr, "send error: %s\n", strerror(errno));
            return errno;
        }
    }
    return 0;
}

bool isValidUsername(const char *username) { return true; }
unsigned char *getCliKey(const char *username) { return clientKey; }
unsigned char *getCliTgsKey() { return cliTgsKey; }

unsigned char *pkgMsgB(char *msgB, unsigned char *cliTgsKey,
                       struct sockaddr *cliAddr, unsigned char *clientID) {
    strcpy(msgB, clientID);
    strcat(msgB, cliAddr->sa_data);
    for (int i = 0; i < 14 - strlen(cliAddr->sa_data); i++) {
        strcat(msgB, "0");
    }

    time_t validate;
    time(&validate);
    validate += 10 * 60;
    unsigned char timebuffer[50];
    sprintf(timebuffer, "%ld", validate);
    strcat(msgB, timebuffer);

    strcat(msgB, cliTgsKey);
    return msgB;
}
