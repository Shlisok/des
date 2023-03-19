#include <stdio.h>
#include <string.h>
#include "DES_Core.h"

int main() {
    char key[] = "hello,w";
    unsigned char data[sizeof (key)];
    memcpy(data,key,sizeof (key));

    unsigned char subkeys[16][6];
    des_key_generate(data,subkeys);

    for (int i = 0; i < 16; i++) {
        printf("Subkey %d: ", i);
        for (int j = 0; j < 6; j++) {
            for (int k = 7; k >= 0; k--) {
                unsigned char bit = (subkeys[i][j] >> k) & 1;
                printf("%d", bit);
            }
            printf(" ");
        }
        printf("\n");
    }



    return 0;
}
