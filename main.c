#include <stdio.h>
#include <string.h>
#include "DES_Core.h"

int main() {
    char m[9];
    printf("请输入8位明文:");
    scanf("%s",m);
    unsigned char data[8];
    memcpy(data,m, 8);


    char k[9];
    unsigned char key[8]; //种子密钥
    unsigned char subkeys[16][6]; //轮密钥
    printf("请输入8位密钥:");
    scanf("%s",k);
    memcpy(key, k, 8);

    des_key_generate(key,subkeys); //生成密钥



    printf("明文:");
    for (int i = 0; i < 8; ++i) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (data[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n\n");

    printf("密钥:\n");
    for (int i = 0; i < 16; ++i) {
        printf("第%d轮密钥:",i + 1);
        for (int j = 0; j < 6; ++j) {
            for (int l = 7; l >= 0; l--) {
                printf("%d", (subkeys[i][j] >> l) & 1);
            }
            printf(" ");
        }
        printf("\n");
    }
    printf("\n");

    unsigned char ciphertext[8];
    encrypt_8Byte(data, subkeys, ciphertext);
    printf("密文:");
    for (int i = 0; i < 8; ++i) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (ciphertext[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n");

    return 0;
}
