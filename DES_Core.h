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



#endif //DES_DES_CORE_H
