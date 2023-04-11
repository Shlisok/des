//
// Created by 孙海龙 on 2023/3/18.
// DES算法主要实现部分
//shlisok

#ifndef DES_DES_CORE_H
#define DES_DES_CORE_H

//密钥生成部分
void key_permutation(const unsigned char *key,unsigned char *key_56); //密钥初始置换,从64位密钥置换为56位密钥
void key_left_permutation(unsigned char *key_28,int count); //将密钥左移，count是当前轮数
void key_merge_subkey(unsigned char *left_key_28,unsigned char *right_key_28,unsigned char *subkey); //将两个28key合并位子密钥
void key_subkeys_generate(unsigned char *key_56,unsigned char subkeys[][6]); //转置后的56位密钥生成16轮子密钥
int des_key_generate(unsigned char *originalKey,unsigned char subkeys[][6]); //密钥生成，传入64位密钥，计算16轮48位密钥

//轮函数部分
void F_E_box_permutation(unsigned char *data_32,unsigned char *data_48); //将32位明文利用E盒进行扩展，扩展为48位
void F_xor_data_key(unsigned char *data_48,unsigned char *subkey,unsigned char *result); //将扩展后的48位明文与该轮次子密钥异或计算
void F_S_box_permutation(unsigned char data_6bit,unsigned char *result_4bit,int n); //将异或结果送入Sn，计算结果
void F_S_box_result(unsigned char *data_xored_48bit,unsigned char *result_32bit); //将异或后的数据进行S盒处理，生成32位的结果
void F_P_box_permutation(unsigned char *data_s_result,unsigned char *result); //将S盒输出的32位进行P盒置换
void F_function(unsigned char *data_32,unsigned char *subkey,unsigned char *result); //f函数，输入32位的data，计算经过f函数处理后的值
void wheel_function(unsigned char *left, unsigned char *right, unsigned char *subkey, int mode); //轮函数实现部分，mode为模式选择

void permutation(unsigned char *data,const int *table); //根据传入的表对64位明文进行置换
void initial_permutation(unsigned char *data);  //初始置换
void initial_permutation_inverse(unsigned char *data);  //初始置换
void encrypt_8Byte(const unsigned char *byte8, unsigned char subkeys[][6], unsigned char *result); //8字节的加密解密函数



#endif //DES_DES_CORE_H
