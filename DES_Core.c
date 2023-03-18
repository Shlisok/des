#include <string.h>
#include "DES_Core.h"
#include "DES_Table.h"

//根据传入的表对64位明文进行置换
void permutation(unsigned char *data,const int *table) {
    unsigned char temp[8]; //创建temp，用于存储原始数据
    memcpy(temp,data,8);    //存储原始数据

    memset(data, 0, 8); //将data内存置0，方便后存入新数据

    for (int i = 0; i < 64; ++i) {
        int row = (table[i] - 1) / 8; //行，置换表从1开始，而在数组应从0开始
        int col = (table[i] - 1) % 8; //列

        //先找到要取的位，然后右移高位填0，最后和"1"做与运算，舍弃全部高位，只取最低位(所取位)
        int bit = (temp[row] >> (7 - col)) & 1;
        //先计算bit应该是第几位，左移补0，通过按位或运算的方式，合并到原字节上
        data[i / 8] |= (bit << (7 - i % 8));

    }
}
//初始置换
void initial_permutation(unsigned char *data) {
    permutation(data,IP_table);
}

//初始逆置换
void initial_permutation_inverse(unsigned char *data) {
    permutation(data,IP_inv_table);
}

//密钥初始置换,从64位密钥置换为56位密钥，这里使用长度为7的*char存储56位置换后的密钥
void key_permutation(const unsigned char *key,unsigned char *key_56) {
    memset(key_56, 0, 7); //将key_56内存置0，方便后存入新数据
    for (int i = 0; i < 56; ++i) {
        int row = (PC_1[i] - 1) / 8; //行，置换表从1开始，而在数组应该从0开始
        int col = (PC_1[i] - 1) % 8; //列

        //先找到要取的位，然后右移高位填0，最后和"1"做与运算，舍弃全部高位，只取最低位(所取位)
        int bit = (key[row] >> (7 - col)) & 1;
        //先计算bit应该是第几位，左移补0，通过按位或运算的方式，合并到原字节上
        key_56[i / 8] |= (bit << (7 - i % 8));
    }
}