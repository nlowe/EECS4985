#pragma once

/** Check to see if the two buffers are equal */
inline bool check(char* a, char* b, size_t len)
{
    for(auto i = 0; i < len; i++)
    {
        if(a[i] != b[i]) return false;
    }

    return true;
}

int aes_encrypt_ecb_128(char* key, char* data, char* expected, size_t len);
int aes_encrypt_cbc_128(char* key, char* iv, char* data, char* expected, size_t len);

int aes_encrypt_ecb_192(char* key, char* data, char* expected, size_t len);
int aes_encrypt_cbc_192(char* key, char* iv, char* data, char* expected, size_t len);

int aes_encrypt_ecb_256(char* key, char* data, char* expected, size_t len);
int aes_encrypt_cbc_256(char* key, char* iv, char* data, char* expected, size_t len);

int aes_decrypt_ecb_128(char* key, char* data, char* expected, size_t len);
int aes_decrypt_cbc_128(char* key, char* iv, char* data, char* expected, size_t len);

int aes_decrypt_ecb_192(char* key, char* data, char* expected, size_t len);
int aes_decrypt_cbc_192(char* key, char* iv, char* data, char* expected, size_t len);

int aes_decrypt_ecb_256(char* key, char* data, char* expected, size_t len);
int aes_decrypt_cbc_256(char* key, char* iv, char* data, char* expected, size_t len);

int sha512_digest(char* message, char* expected, size_t len);