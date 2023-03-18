#include <stdio.h>
#include <string.h>
#include "DES_Core.h"

int main() {
    char string[] = "hello,w";
    unsigned char data[sizeof (string)];
    unsigned char key[7];
    memcpy(data,string,sizeof (string));

    key_permutation(data,key);
    //debug调试，查看置换是否成功
    int a = 1;

    char new_string[sizeof (string)];
    for (int i = 0; i < sizeof(string); ++i) {
        new_string[i] = (char)data[i];
    }
    printf("%s",new_string);
    return 0;
}
