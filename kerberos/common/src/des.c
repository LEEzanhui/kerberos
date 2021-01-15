// #include "des.h"

// #include <string.h>

// uint8_t *encrypt(const uint8_t *key, const uint8_t *msg, uint8_t *crypt) {
//     strcpy(crypt, "e: ");
//     strcat(crypt, msg);
//     return crypt;
// }

// uint8_t *decrypt(const uint8_t *key, const uint8_t *crypt, uint8_t *msg) {
//     strcpy(msg, &crypt[3]);
//     return msg;
// }

#include "des.h"

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
// #include "table.h"

// IP置换表
int initial_msg_permutation[] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

// PC-1置换表
int initial_key_permutation[] = {
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43,
    35, 27, 19, 11, 3,  60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7,  62, 54,
    46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

// PC-2置换表
int sub_key_permutation[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
                             23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
                             41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                             44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

// 密钥位移
int key_shift[] = {-1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// IP^-1置换表
int inverse_msg_permutation[] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};

// E-扩展规则
int msg_expansion[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
                       8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                       16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                       24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

// P-置换表
int right_sub_msg_permutation[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                                   26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                                   3,  9, 19, 13, 30, 6,  22, 11, 4,  25};

// S-盒
int sBox[][64] = {
    {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0, 7,
     0,  15, 7,  4, 14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3, 8,
     4,  1,  14, 8, 13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5, 0,
     15, 12, 8,  2, 4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6, 13},

    {15, 1,  8,  14, 6,  11, 3,  4,  9,  7, 2,  13, 12, 0, 5,  10,
     3,  13, 4,  7,  15, 2,  8,  14, 12, 0, 1,  10, 6,  9, 11, 5,
     0,  14, 7,  11, 10, 4,  13, 1,  5,  8, 12, 6,  9,  3, 2,  15,
     13, 8,  10, 1,  3,  15, 4,  2,  11, 6, 7,  12, 0,  5, 14, 9},

    {10, 0,  9,  14, 6, 3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
     13, 7,  0,  9,  3, 4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
     13, 6,  4,  9,  8, 15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
     1,  10, 13, 0,  6, 9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12},

    {7,  13, 14, 3, 0,  6,  9,  10, 1,  2, 8, 5,  11, 12, 4,  15,
     13, 8,  11, 5, 6,  15, 0,  3,  4,  7, 2, 12, 1,  10, 14, 9,
     10, 6,  9,  0, 12, 11, 7,  13, 15, 1, 3, 14, 5,  2,  8,  4,
     3,  15, 0,  6, 10, 1,  13, 8,  9,  4, 5, 11, 12, 7,  2,  14},

    {2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0, 14, 9,
     14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9, 8,  6,
     4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3, 0,  14,
     11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4, 5,  3},

    {12, 1,  10, 15, 9, 2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
     10, 15, 4,  2,  7, 12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
     9,  14, 15, 5,  2, 8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
     4,  3,  2,  12, 9, 5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13},

    {4,  11, 2,  14, 15, 0, 8,  13, 3,  12, 9, 7,  5,  10, 6, 1,
     13, 0,  11, 7,  4,  9, 1,  10, 14, 3,  5, 12, 2,  15, 8, 6,
     1,  4,  11, 13, 12, 3, 7,  14, 10, 15, 6, 8,  0,  5,  9, 2,
     6,  11, 13, 8,  1,  4, 10, 7,  9,  5,  0, 15, 14, 2,  3, 12},

    {13, 2,  8,  4, 6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
     1,  15, 13, 8, 10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
     7,  11, 4,  1, 9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
     2,  1,  14, 7, 4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11}};

// 16组子密钥
unsigned char k[17][8];
unsigned char c[17][4];
unsigned char d[17][4];

// 初始置换
void do_initial_msg_permutation(unsigned char* msg, unsigned char* initial) {
    int shift;
    unsigned char mid_byte;

    for (int i = 0; i < 64; i++) {
        shift = initial_msg_permutation[i];
        mid_byte = 0x80 >> ((shift - 1) % 8);
        mid_byte &= msg[(shift - 1) / 8];
        mid_byte <<= ((shift - 1) % 8);

        initial[i / 8] |= (mid_byte >> i % 8);
    }
}

// PC-1置换
void do_initial_key_permutation(unsigned char* main_key) {
    int shift;
    unsigned char mid_byte;
    for (int i = 0; i < 8; i++) {
        k[0][i] = 0;
    }

    // PC-1置换
    for (int i = 0; i < 56; i++) {
        shift = initial_key_permutation[i];
        mid_byte = 0x80 >> ((shift - 1) % 8);
        mid_byte &= main_key[(shift - 1) / 8];
        mid_byte <<= ((shift - 1) % 8);

        k[0][i / 8] |= (mid_byte >> i % 8);
    }
}

// P-置换
void do_right_sub_msg_permutation(unsigned char* r, unsigned char* ser) {
    int shift;
    unsigned char mid_byte;

    for (int i = 0; i < 4; i++) {
        r[i] = 0;
    }

    for (int i = 0; i < 32; i++) {
        shift = right_sub_msg_permutation[i];
        mid_byte = 0x80 >> ((shift - 1) % 8);
        mid_byte &= ser[(shift - 1) / 8];
        mid_byte <<= ((shift - 1) % 8);

        r[i / 8] |= (mid_byte >> i % 8);
    }
}

// 循环左移
void do_shift_left(unsigned char* half, unsigned char mid_byte, int shift,
                   int index) {
    unsigned char first, second, third, fourth;
    first = mid_byte & half[0];
    second = mid_byte & half[1];
    third = mid_byte & half[2];
    fourth = mid_byte & half[3];

    half[0] <<= shift;
    half[0] |= (second >> (8 - shift));
    half[1] <<= shift;
    half[1] |= (third >> (8 - shift));
    half[2] <<= shift;
    half[2] |= (fourth >> (8 - shift));
    half[3] <<= shift;
    half[3] |= (first >> (4 - shift));
}

// 迭代
void do_iteration(unsigned char* L, unsigned char* R, int index, int mode) {
    int key_index;
    int shift;
    unsigned char mid_byte;
    unsigned char l[4], r[4], er[6], ser[4];
    memcpy(l, R, 4);
    memset(er, 0, 6);

    // 将长度为32位的串 R_i-1 作 E-扩展，得到一个48位的串 E(R_i-1)
    for (int i = 0; i < 48; i++) {
        shift = msg_expansion[i];
        mid_byte = 0x80 >> ((shift - 1) % 8);
        mid_byte &= R[(shift - 1) / 8];
        mid_byte <<= ((shift - 1) % 8);

        er[i / 8] |= (mid_byte >> i % 8);
    }

    if (mode == 1) {
        key_index = 17 - index;
    } else {
        key_index = index;
    }

    // 将 E(R_i-1) 和长度为48位的子密钥 K_i 作48位二进制串按位异或运算
    for (int i = 0; i < 6; i++) {
        er[i] ^= k[key_index][i];
    }

    unsigned char row, col;

    for (int i = 0; i < 4; i++) {
        ser[i] = 0;
    }

    // S-盒6-4转换
    col = 0;
    col |= ((er[0] & 0x78) >> 3);
    row = 0;
    row |= ((er[0] & 0x80) >> 6);
    row |= ((er[0] & 0x04) >> 2);

    ser[0] |= ((unsigned char)sBox[0][row * 16 + col] << 4);

    col = 0;
    col |= ((er[0] & 0x01) << 3);
    col |= ((er[1] & 0xE0) >> 5);
    row = 0;
    row |= (er[0] & 0x02);
    row |= ((er[1] & 0x10) >> 4);

    ser[0] |= (unsigned char)sBox[1][row * 16 + col];

    col = 0;
    col |= ((er[1] & 0x07) << 1);
    col |= ((er[2] & 0x80) >> 7);
    row = 0;
    row |= ((er[1] & 0x08) >> 2);
    row |= ((er[2] & 0x40) >> 6);

    ser[1] |= ((unsigned char)sBox[2][row * 16 + col] << 4);

    col = 0;
    col |= ((er[2] & 0x1E) >> 1);
    row = 0;
    row |= ((er[2] & 0x20) >> 4);
    row |= (er[2] & 0x01);

    ser[1] |= (unsigned char)sBox[3][row * 16 + col];

    col = 0;
    col |= ((er[3] & 0x78) >> 3);
    row = 0;
    row |= ((er[3] & 0x80) >> 6);
    row |= ((er[3] & 0x04) >> 2);

    ser[2] |= ((unsigned char)sBox[4][row * 16 + col] << 4);

    col = 0;
    col |= ((er[3] & 0x01) << 3);
    col |= ((er[4] & 0xE0) >> 5);
    row = 0;
    row |= (er[3] & 0x02);
    row |= ((er[4] & 0x10) >> 4);

    ser[2] |= (unsigned char)sBox[5][row * 16 + col];

    col = 0;
    col |= ((er[4] & 0x07) << 1);
    col |= ((er[5] & 0x80) >> 7);
    row = 0;
    row |= ((er[4] & 0x08) >> 2);
    row |= ((er[5] & 0x40) >> 6);

    ser[3] |= ((unsigned char)sBox[6][row * 16 + col] << 4);

    col = 0;
    col |= ((er[5] & 0x1E) >> 1);
    row = 0;
    row |= ((er[5] & 0x20) >> 4);
    row |= (er[5] & 0x01);

    ser[3] |= (unsigned char)sBox[7][row * 16 + col];

    do_right_sub_msg_permutation(r, ser);

    for (int i = 0; i < 4; i++) {
        r[i] ^= L[i];
    }

    for (int i = 0; i < 4; i++) {
        L[i] = l[i];
        R[i] = r[i];
    }
}

// 逆置换
void do_inverse_msg_permutation(unsigned char* msg,
                                unsigned char* processed_piece) {
    int shift;
    unsigned char mid_byte;
    for (int i = 0; i < 64; i++) {
        shift = inverse_msg_permutation[i];
        mid_byte = 0x80 >> ((shift - 1) % 8);
        mid_byte &= msg[(shift - 1) / 8];
        mid_byte <<= ((shift - 1) % 8);

        processed_piece[i / 8] |= (mid_byte >> i % 8);
    }
}

// 随机生成密钥
void generateKey(unsigned char* key) {
    for (int i = 0; i < 8; i++) {
        key[i] = rand() % 255;
    }
}

// 根据密钥生成子密钥
void generateSubKey(unsigned char* main_key) {
    for (int i = 0; i < 17; i++) {
        for (int j = 0; j < 8; j++) {
            k[i][j] = 0;
        }
        for (int l = 0; l < 4; l++) {
            c[i][l] = 0;
            d[i][l] = 0;
        }
    }

    int shift;
    unsigned char mid_byte;

    do_initial_key_permutation(main_key);

    // 赋值c0和d0
    for (int i = 0; i < 3; i++) {
        c[0][i] = k[0][i];
    }

    c[0][3] = k[0][3] & 0xF0;

    for (int i = 0; i < 3; i++) {
        d[0][i] = (k[0][i + 3] & 0x0F) << 4;
        d[0][i] |= (k[0][i + 4] & 0xF0) >> 4;
    }

    d[0][3] = (k[0][6] & 0x0F) << 4;

    // 循环左移一个或两个位置
    for (int i = 1; i < 17; i++) {
        for (int j = 0; j < 4; j++) {
            c[i][j] = c[i - 1][j];
            d[i][j] = d[i - 1][j];
        }

        shift = key_shift[i];
        if (shift == 1) {
            mid_byte = 0x80;
        } else {
            mid_byte = 0xC0;
        }

        do_shift_left(c[i], mid_byte, shift, i);
        do_shift_left(d[i], mid_byte, shift, i);

        // PC-2置换
        for (int j = 0; j < 48; j++) {
            shift = sub_key_permutation[j];
            if (shift <= 28) {
                mid_byte = 0x80 >> ((shift - 1) % 8);
                mid_byte &= c[i][(shift - 1) / 8];
                mid_byte <<= ((shift - 1) % 8);
            } else {
                mid_byte = 0x80 >> ((shift - 29) % 8);
                mid_byte &= d[i][(shift - 29) / 8];
                mid_byte <<= ((shift - 29) % 8);
            }

            k[i][j / 8] |= (mid_byte >> j % 8);
        }
    }
}

// 加密主过程
void encryptionMsg(unsigned char* message_piece,
                   unsigned char* processed_piece) {
    int shift;
    unsigned char mid_byte;

    unsigned char msg[8];
    memset(msg, 0, 8);
    memset(processed_piece, 0, 8);

    do_initial_msg_permutation(message_piece, msg);

    // 赋值L和R
    unsigned char L[4], R[4];
    for (int i = 0; i < 4; i++) {
        L[i] = msg[i];
        R[i] = msg[i + 4];
    }

    // 16次迭代
    int key_index;
    for (int j = 1; j <= 16; j++) {
        do_iteration(L, R, j, 0);
    }

    for (int i = 0; i < 4; i++) {
        msg[i] = R[i];
        msg[4 + i] = L[i];
    }

    // 逆置换
    do_inverse_msg_permutation(msg, processed_piece);

    return;
}

// 解密主过程
void decryptionMsg(unsigned char* message_piece,
                   unsigned char* processed_piece) {
    int shift;
    unsigned char mid_byte;

    unsigned char msg[8];
    memset(msg, 0, 8);
    memset(processed_piece, 0, 8);

    do_initial_msg_permutation(message_piece, msg);

    // 赋值L和R
    unsigned char L[4], R[4];
    for (int i = 0; i < 4; i++) {
        L[i] = msg[i];
        R[i] = msg[i + 4];
    }

    // 16次迭代
    int key_index;
    for (int j = 1; j <= 16; j++) {
        do_iteration(L, R, j, 1);
    }

    for (int i = 0; i < 4; i++) {
        msg[i] = R[i];
        msg[4 + i] = L[i];
    }

    // 逆置换
    do_inverse_msg_permutation(msg, processed_piece);

    return;
}

void encryption(unsigned char* message_piece, unsigned char* processed_piece) {
    int i;
    int index = 0;
    unsigned char cip[10];
    unsigned char message[10];
    processed_piece[0] = 0;
    // printf("me: %s\n", message_piece);
    memset(message, 0, sizeof(message));
    memset(processed_piece, 0, sizeof(processed_piece));
    for (i = 0; message_piece[index] != '\0'; i++, index++) {
        message[i] = message_piece[index];
        // printf("en: %s\n", message);
        if (i == 7) {
            i = -1;
            memset(cip, 0, sizeof(cip));
            encryptionMsg(message, cip);
            strcat(processed_piece, cip);
            memset(message, 0, sizeof(message));
        }
    }

    if (i != -1) {
        for (int i = index % 8; i < 8; i++) message[i] = 8 - index % 8;
        message[8] = 0;
        memset(cip, 0, sizeof(cip));
        encryptionMsg(message, cip);
        strcat(processed_piece, cip);
    }
}
void decryption(unsigned char* message_piece, unsigned char* processed_piece) {
    int i;
    int index = 0;
    unsigned char cip[10];
    unsigned char message[10];
    processed_piece[0] = 0;
    memset(message, 0, sizeof(message));
    memset(processed_piece, 0, sizeof(processed_piece));
    for (i = 0; message_piece[index] != '\0'; i++, index++) {
        message[i] = message_piece[index];
        if (i == 7) {
            i = -1;
            memset(cip, 0, sizeof(cip));
            decryptionMsg(message, cip);
            strcat(processed_piece, cip);
            memset(message, 0, sizeof(message));
        }
    }

    // if (i != 0) {
    //     for (int i = 0; i < 8; i++) message[i] = 8 - i % 8;
    //     memset(cip, 0, sizeof(cip));
    //     encryptionMsg(message, cip);
    //     strcat(processed_piece, cip);
    // }
}