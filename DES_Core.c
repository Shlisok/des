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

//将密钥左移，count是当前轮数，key_28仅前28位为有效位，剩余4位可以考虑做校验位
void key_left_permutation(unsigned char *key_28,int count){
    for (int i = 0; i < key_left_table[count]; ++i) {
        //取下最左边的一位，最后添加到末尾
        int temp = (key_28[0] >> 7) & 1;
        for (int j = 0; j < 3; ++j) {
            //左移一位
            key_28[j] <<= 1;
            //取下下个字节的开头
            int bit = (key_28[j + 1] >> 7) & 1;
            //补到当前字节的末尾
            key_28[j] |= bit;
        }
        //最后一字节左移一位
        key_28[3] <<= 1;
        //将key_28第一位补到最后一位
        key_28[3] |= (temp << 4);
    }
}

//将两个28key合并为长度为48子密钥(*功能待测试)
void key_merge_subkey(unsigned char *left_key_28,unsigned char *right_key_28,unsigned char *subkey){
    memset(subkey,0,6); //将data内存置0，方便后存入新数据
    for (int i = 0; i < 48; ++i) {
        if (PC_2[i] <= 28) {
            //计算所取位位于第几个字节的第几位
            int row = (PC_2[i] - 1) / 8;
            int col = (PC_2[i] - 1) % 8;
            //取出所要的位
            int bit = (left_key_28[row] >> (7 - col)) & 1;
            subkey[i / 8] |= (bit << (7 - i % 8));
        } else {
            //计算所取位位于第几个字节的第几位
            int row = (PC_2[i] - 29) / 8;
            int col = (PC_2[i] - 29) % 8;
            //取出所要的位
            int bit = (right_key_28[row] >> (7 - col)) & 1;
            subkey[i / 8] |= (bit << (7 - i % 8));
        }
    }
}

//转置后的56位密钥生成16轮子密钥
void key_subkeys_generate(unsigned char *key_56,unsigned char subkeys[][6]){
    //两个长度4字节(28位)的子密钥
    unsigned char left_key_28[4];
    unsigned char right_key_28[4];

    for (int i = 0; i < 3; ++i) {
        //left_key赋值
        left_key_28[i] |= key_56[i];
        //right_key赋值，因为28不是8的倍数，需要做拼接
        right_key_28[i] |= ((key_56[i + 3] << 4) | (key_56[i + 4] >> 4));
    }
    //left_key的最后一字节，仅前四位有效值，抹掉低四位
    left_key_28[3] |= (key_56[3] & 0xF0);
    //right_key的最后一字节，仅有前四位有效值，左移四位
    right_key_28[3] |= (key_56[6] << 4);

    for (int i = 0; i < 16; ++i) {
        //开始移位
        key_left_permutation(left_key_28,i);
        key_left_permutation(right_key_28,i);
        //移位后合并为48位密钥
        unsigned char subkey[6];
        key_merge_subkey(left_key_28,right_key_28,subkey);
        //将生成的子密钥存储到数组中
        memcpy(subkeys[i],subkey,6);
    }
}

//完成函数，传入64位密钥，计算16轮48位密钥（先不考虑奇偶检验位）
int des_key_generate(unsigned char *key,unsigned char subkeys[][6]){
    /*
     * 应有奇偶校验
     * 因为时间原因先不考虑
     * 待后期设计密钥生成时再做考虑
     * return 返回奇偶校验结果
     * */

    //存储转置后56位密钥
    unsigned char key_56[7];
    key_permutation(key,key_56);

    //根据转置后的56位密钥生成16轮密钥
    key_subkeys_generate(key_56,subkeys);

    return 0;
}

