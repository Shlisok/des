//
// Created by 孙海龙 on 2023/3/18.
// DES算法主要实现部分
//

#ifndef DES_DES_CORE_H
#define DES_DES_CORE_H

void permutation(unsigned char *data,const int *table); //根据传入的表对64位明文进行置换
void initial_permutation(unsigned char *data);  //初始置换
void initial_permutation_inverse(unsigned char *data);  //初始置换
void key_permutation(const unsigned char *key,unsigned char *key_56); //密钥初始置换,从64位密钥置换为56位密钥
void key_left_permutation(unsigned char *key_28,int count); //将密钥左移，count是当前轮数
void key_merge_subkey(unsigned char *left_key_28,unsigned char *right_key_28,unsigned char *subkey); //将两个28key合并位子密钥
void key_subkeys_generate(unsigned char *key_56,unsigned char subkeys[][6]); //转置后的56位密钥生成16轮子密钥
int des_key_generate(unsigned char *key,unsigned char subkeys[][6]); //密钥生成，传入64位密钥，计算16轮48位密钥


#endif //DES_DES_CORE_H
