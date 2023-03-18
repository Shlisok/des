#include <stdio.h>
#include <string.h>
#include "DES_Core.h"

int main() {
    char string[] = "hello,w";
    unsigned char data[sizeof (string)];
    memcpy(data,string,sizeof (string));

    initial_permutation(data);
    initial_permutation_inverse(data);

    char new_string[sizeof (string)];
    for (int i = 0; i < sizeof(string); ++i) {
        new_string[i] = (char)data[i];
    }
    printf("%s",new_string);
    return 0;
}
