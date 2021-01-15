#if !defined(DES_H)
#define DES_H

// typedef unsigned char uint8_t;

// uint8_t *encrypt(const uint8_t *key, const uint8_t *msg, uint8_t *crypt);
// uint8_t *decrypt(const uint8_t *key, const uint8_t *crypt, uint8_t *msg);

void generateSubKey(unsigned char *main_key);
void encryptionMsg(unsigned char *message_piece,
                   unsigned char *processed_piece);
void decryptionMsg(unsigned char *message_piece,
                   unsigned char *processed_piece);

void encryption(unsigned char *message_piece, unsigned char *processed_piece);
void decryption(unsigned char *message_piece, unsigned char *processed_piece);

#endif  // DES_H
