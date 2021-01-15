#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "des.h"
#include "utils.h"

#define BUFSIZE 1024

unsigned char *serviceID = "000000";
unsigned char *clientID = "username";
unsigned char *username = "username";
unsigned char *clientKey = "12345678";

time_t msgGTS;

int connServSocket(const char *asIp, int asPort);
int asAuth(const char *username, unsigned char *msgA, unsigned char *msgB);
int tgsAuth(unsigned char *msgC, unsigned char *cliTgsKey, unsigned char *msgE,
            unsigned char *msgF);
int ssAuth(unsigned char *msgE, unsigned char *cliSsKey, unsigned char *msgH);
unsigned char *getCliKey(const char *username);

unsigned char *pkgMsgD(unsigned char *msgD);
unsigned char *pkgMsgG(unsigned char *msgG);

int main(int argc, char const *argv[]) {
    // char username[10];
    // strcpy(username, "username");
    printf("username: %s\n", username);
    printf("clientID: %s\n", username);
    printf("serviceID: %s\n", serviceID);

    unsigned char *cliKey = getCliKey(username);
    printf("clientKey: %s\n\n", cliKey);

    unsigned char msgA[BUFSIZE], msgB[BUFSIZE];
    asAuth(username, msgA, msgB);

    unsigned char cliTgsKey[BUFSIZE];
    generateSubKey(cliKey);
    // decryptionMsg(msgA, cliTgsKey);
    decryption(msgA, cliTgsKey);

    printf("msgA: ");
    for (int i = 0; msgA[i] != '\0'; i++) {
        printf("%02x", msgA[i]);
    }
    printf("\n");

    printf("msgB: ");
    for (int i = 0; msgB[i] != '\0'; i++) {
        printf("%02x", msgB[i]);
    }
    printf("\n");

    // printf("msgA: %02x\n", msgA);
    // printf("msgB: %02x\n", msgB);
    printf("cliTgsKey: %s\n", cliTgsKey);

    unsigned char msgC[BUFSIZE], msgE[BUFSIZE], msgF[BUFSIZE];
    strcpy(msgC, serviceID);
    strcat(msgC, msgB);
    tgsAuth(msgC, cliTgsKey, msgE, msgF);

    unsigned char cliSsKey[BUFSIZE];
    generateSubKey(cliTgsKey);
    decryption(msgF, cliSsKey);

    printf("msgE: ");
    for (int i = 0; msgE[i] != '\0'; i++) {
        printf("%02x", msgE[i]);
    }
    printf("\n");

    printf("msgF: ");
    for (int i = 0; msgF[i] != '\0'; i++) {
        printf("%02x", msgF[i]);
    }
    printf("\n");

    // printf("msgE: %s\n", msgE);
    // printf("msgF: %s\n", msgF);
    printf("cliSsKey: %s\n", cliSsKey);

    unsigned char msgH[BUFSIZE];
    ssAuth(msgE, cliSsKey, msgH);

    unsigned char getH[BUFSIZE];
    generateSubKey(cliSsKey);
    decryption(msgH, getH);

    printf("msgH: ");
    for (int i = 0; msgH[i] != '\0'; i++) {
        printf("%02x", msgH[i]);
    }
    printf("\n");
    // printf("msgH: %s\n", msgH);
    printf("msgH after dec: %s\n", getH);

    unsigned char recCliID[BUFSIZE], recTimestamp[BUFSIZE];
    strncpy(recCliID, getH, 8);
    recCliID[8] = 0;
    strcpy(recTimestamp, getH + 8);
    if (strcmp(recCliID, clientID) != 0) {
        printf("recClientID: %s\n", recCliID);
        printf("Wrong clientID\n");
        return 0;
    }

    unsigned char timebuffer[50];
    memset(timebuffer, 0, sizeof(timebuffer));
    strncpy(timebuffer, recTimestamp, 10);
    timebuffer[10] = 0;
    printf("timestamp: %s\n", timebuffer);
    time_t msgHTS = atol(timebuffer);

    if ((msgHTS - msgGTS - 1.0) > 0.001) {
        printf("recTimestamp: %s\n", recTimestamp);
        printf("Wrong timestamp\n");
        return 0;
    }

    printf("Success!\n");

    return 0;
}

int asAuth(const char *username, unsigned char *msgA, unsigned char *msgB) {
    int sockfd = connServSocket(ASIP, ASPORT);

    printf("\nsend request\n");
    int len = send(sockfd, username, strlen(username), 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nreceive msgA & msgB\n");
    int msgLenA = recv(sockfd, msgA, BUFSIZE - 1, 0);
    msgA[msgLenA] = '\0';
    int msgLenB = recv(sockfd, msgB, BUFSIZE - 1, 0);
    msgB[msgLenB] = '\0';

    close(sockfd);
}

int tgsAuth(unsigned char *msgC, unsigned char *cliTgsKey, unsigned char *msgE,
            unsigned char *msgF) {
    int sockfd = connServSocket(TGSIP, TGSPORT);

    printf("\nsend msgC\n");
    // printf("msgC: %s\n", msgC);
    printf("msgC: ");
    for (int i = 0; msgC[i] != '\0'; i++) {
        printf("%02x", msgC[i]);
    }
    printf("\n");

    int len = send(sockfd, msgC, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nsend msgD\n");
    unsigned char msgD[BUFSIZE], sendD[BUFSIZE];
    generateSubKey(cliTgsKey);
    pkgMsgD(msgD);
    encryption(msgD, sendD);

    // printf("sendD: %s\n", sendD);
    printf("msgD before enc: %s\n", msgD);

    printf("msgD: ");
    for (int i = 0; sendD[i] != '\0'; i++) {
        printf("%02x", sendD[i]);
    }
    printf("\n");

    len = send(sockfd, sendD, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nreceive msgE & msgF\n");

    int msgLenE = recv(sockfd, msgE, BUFSIZE - 1, 0);
    msgE[msgLenE] = '\0';
    int msgLenF = recv(sockfd, msgF, BUFSIZE - 1, 0);
    msgF[msgLenF] = '\0';

    close(sockfd);
}

int ssAuth(unsigned char *msgE, unsigned char *cliSsKey, unsigned char *msgH) {
    int sockfd = connServSocket(SSIP, SSPORT);

    printf("\nsend msgE\n");
    // printf("msgE: %s\n", msgE);
    printf("msgE: ");
    for (int i = 0; msgE[i] != '\0'; i++) {
        printf("%02x", msgE[i]);
    }
    printf("\n");

    int len = send(sockfd, msgE, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nsend msgG\n");
    unsigned char msgG[BUFSIZE], sendG[BUFSIZE];
    generateSubKey(cliSsKey);
    pkgMsgG(msgG);
    encryption(msgG, sendG);

    // printf("sendG: %s\n", sendG);
    printf("msgG before enc: %s\n", msgG);

    printf("msgG: ");
    for (int i = 0; sendG[i] != '\0'; i++) {
        printf("%02x", sendG[i]);
    }
    printf("\n");

    len = send(sockfd, sendG, BUFSIZE - 1, 0);
    if (len < 0) {
        fprintf(stderr, "send error: %s\n", strerror(errno));
        return errno;
    }

    printf("\nreceive msgH\n");

    int msgLenH = recv(sockfd, msgH, BUFSIZE - 1, 0);
    msgH[msgLenH] = '\0';

    close(sockfd);
}

int connServSocket(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        fprintf(stderr, "create socket error: %s\n", strerror(errno));
        exit(errno);
    }

    int res;
    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    res = inet_pton(AF_INET, ip, &servAddr.sin_addr);
    if (res <= 0) {
        fprintf(stderr, "inet_pton error (%d)\n", res);
        exit(-1);
    }

    res = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr));
    if (res < 0) {
        fprintf(stderr, "connect error: %s\n", strerror(errno));
        exit(errno);
    }
    return sockfd;
}

unsigned char *getCliKey(const char *username) { return clientKey; }

unsigned char *pkgMsgD(unsigned char *msgD) {
    strcpy(msgD, clientID);

    time_t start;
    time(&start);
    unsigned char timebuffer[50];
    sprintf(timebuffer, "%ld", start);
    printf("msgD timestamp: %s\n", timebuffer);

    strcat(msgD, timebuffer);
    return msgD;
}

unsigned char *pkgMsgG(unsigned char *msgG) {
    strcpy(msgG, clientID);

    time(&msgGTS);
    unsigned char timebuffer[50];
    sprintf(timebuffer, "%ld", msgGTS);
    printf("msgG timestamp: %s\n", timebuffer);

    strcat(msgG, timebuffer);
    return msgG;
}