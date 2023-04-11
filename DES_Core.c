#include <string.h>
#include <printf.h>
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
        left_key_28[i] = key_56[i];
        //right_key赋值，因为28不是8的倍数，需要做拼接
        right_key_28[i] = ((key_56[i + 3] << 4) | (key_56[i + 4] >> 4));
    }
    //left_key的最后一字节，仅前四位有效值，抹掉低四位
    unsigned char a = (key_56[3] & 0xF0);
    left_key_28[3] = (key_56[3] & 0xF0);
    //right_key的最后一字节，仅有前四位有效值，左移四位
    right_key_28[3] = (key_56[6] << 4);

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
int des_key_generate(unsigned char *originalKey,unsigned char subkeys[][6]){
    /*
     * 应有奇偶校验
     * 因为时间原因先不考虑
     * 待后期设计密钥生成时再做考虑
     * return 返回奇偶校验结果
     * */



    unsigned char key[8]; //不能直接在原始密钥的内存空间上修改
    unsigned char key_56[7]; //存储转置后56位密钥

    memcpy(key, originalKey, 8); //复制原始密钥

    //转置为56位
    key_permutation(key,key_56);


    //根据转置后的56位密钥生成16轮密钥
    key_subkeys_generate(key_56,subkeys);

    return 0;
}

//将32位明文利用E盒进行扩展，扩展为48位
void F_E_box_permutation(unsigned char *data_32,unsigned char *data_e_48) {
    memset(data_e_48, 0, 6); //初始化
    for (int i = 0; i < 48; ++i) {
        //计算所取位位于第几个字节的第几位
        int row = (F_E_box[i] - 1) / 8;
        int col = (F_E_box[i] - 1) % 8;
        //取出所要的位
        int bit = (data_32[row] >> (7 - col)) & 1;
        data_e_48[i / 8] |= (bit << (7 - i % 8));
    }
}

//将扩展后的48位明文与该轮次子密钥异或计算
void F_xor_data_key(unsigned char *data_48,unsigned char *subkey,unsigned char *result) {
    for (int i = 0; i < 6; ++i) {
        result[i] = data_48[i] ^ subkey[i];
    }
}

//将后6位有效值的字节结果送入Sn，计算结果
void F_S_box_permutation(unsigned char data_6bit,unsigned char *result_4bit,int n) {
    // 获取S盒对应的行和列
    int row = ((data_6bit & 0b00100000) >> 4) | (data_6bit & 0b00000001);
    int col = (data_6bit & 0b00011110) >> 1;

    //找到对应的数据
    unsigned char value = F_S_box[n][row][col];

    //将result_4bit制0，或上结果，将结果存储在低4位
    *result_4bit = (*result_4bit & 0b00000000) | (value & 0b00001111);
}

//将异或后的数据进行S盒处理，生成32位的结果
void F_S_box_result(unsigned char *data_xored_48bit,unsigned char *result_32bit) {
    unsigned char data_group[8] = {0}; //初始化
    unsigned char data_s_result[8] = {0}; //经过S盒计算后的4位，仅存储在低四位，高4位为0

    for (int i = 0; i < 48; ++i) {
        int row_index = i / 8; //计算原始位置上的字节
        int col_index = i % 8; //计算原始位置上的位数
        //取出所要的位
        int bit = (data_xored_48bit[row_index] >> (7 - col_index)) & 1;

        int row = i / 6; //计算group上的第几个字节
        int col = i % 6; //计算group上的第几位
        data_group[row] |= (bit << (5 - col));
    }

    //传入8个S盒，计算，返回值每个字节只有低4位有效
    for (int i = 0; i < 8; i++) {
        F_S_box_permutation(data_group[i],&data_s_result[i],i);
    }


    memset(result_32bit, 0 ,4); //返回数组初始化
    for (int i = 0; i < 4; ++i) {
        //拼接S盒的返回值，每8个字节的有效值拼接成一个字节
        result_32bit[i] |= (data_s_result[2 * i] << 4);
        result_32bit[i] |= (data_s_result[2 * i + 1] & 0b00001111);
    }
}

//将S盒输出的32位进行P盒置换
void F_P_box_permutation(unsigned char *data_s_result,unsigned char *result) {
    memset(result, 0, 4); //初始化
    for (int i = 0; i < 32; ++i) {
        int row = (P_box[i] - 1) / 8;
        int col = (P_box[i] - 1) % 8;
        int bit = (data_s_result[row] >> (7 - col)) & 1;
        result[i / 8] |= (bit << (7 - i % 8));
    }
}

//f函数，输入32位的data，计算经过f函数处理后的值
void F_function(unsigned char *data_32,unsigned char *subkey,unsigned char *result) {
    unsigned char data_E_48[6]; //经过E盒扩展后的48位数据
    unsigned char data_xored[6]; //与密钥做异或运算后的48位数据
    unsigned char data_s_result[4]; //S盒处理后的32位数据

    //先做扩展，将结果存进data_E_48
    F_E_box_permutation(data_32,data_E_48);
    //将扩展结果与该轮密钥做异或，结果存储进data_xored
    F_xor_data_key(data_E_48,subkey,data_xored);
    //将异或结果送进S盒，结果存进data_s_result
    F_S_box_result(data_xored,data_s_result);
    //最后做P盒置换，结果为F函数的最终结果
    F_P_box_permutation(data_s_result,result);
}

//轮函数实现部分，mode为模式选择
void wheel_function(unsigned char *left, unsigned char *right, unsigned char *subkey, int mode){
    unsigned char temp[4]; //临时存储

    F_function(right,subkey,temp); //f函数

    for (int i = 0; i < 4; ++i) {
        temp[i] ^= left[i]; //异或运算
    }
    if (mode == 1){ //交换位置
        memcpy(left,right,4);
        memcpy(right,temp,4);
    } else{
        memcpy(left,temp,4);
    }
}

//8字节的加密解密函数
void encrypt_8Byte(const unsigned char *byte8, unsigned char subkeys[][6], unsigned char *result) {
    unsigned char data[8]; //需要进行加密的数据
    unsigned char left[4]; //轮函数左部分
    unsigned char right[4]; //轮函数右部分
    unsigned char subkey[6]; //临时存储子密钥

    memcpy(data, byte8, 8); //数据复制
    initial_permutation(data); //初始转置



    for (int i = 0; i < 4; ++i) { //分割两部分
        left[i] = data[i];
        right[i] = data[i + 4];
    }

    for (int i = 0; i < 15; ++i) { //进行轮函数
        memcpy(subkey,subkeys[i],6);
        wheel_function(left, right, subkey, 1);
    }

    //最后一轮不交换位置
    memcpy(subkey,subkeys[15],6);
    wheel_function(left, right, subkey, 0);

    //两个部分合并
    for (int i = 0; i < 4; ++i) {
        result[i] = left[i];
        result[i + 4] = right[i];
    }

    //初始逆置换
    initial_permutation_inverse(result);
}