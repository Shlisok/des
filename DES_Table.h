//
// Created by 孙海龙 on 2023/3/18.
// DES的各种常量表存储
//
#ifndef DES_DES_TABLE_H
#define DES_DES_TABLE_H

const int IP_table[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
}; //初始置换表

const int IP_inv_table[64] = {
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25
};//初始逆置换表

const int PC_1[56] = {
        57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4
};//密钥置换表

const int PC_2[48] = {
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
};

const int key_left_table[16] = {
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
};//密钥左移位数表

const int F_E_box[48] = {
        32,  1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
}; //E盒用数组表示

const char F_S_box[8][4][16] = {
        {
                // S1盒
                {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
        },
        {
                // S2盒
                {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
                {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
        },
        {
                // S3盒
                {10, 13,  1,  5,  8,  4,  3,  0,  9, 14, 15,  6,  7, 12, 11,  2},
                { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
                {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
                { 7,  2, 12,  5,  8,  4,  6, 11, 14,  9,  1, 15, 13,  3, 10,  0}
        },
        {
                // S4盒
                { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
                {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
                {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
                { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
        },
        {
                // S5盒
                { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
                {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
                { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
                {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
        },
        {
                // S6盒
                {12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5},
                { 0,  6, 13,  3,  8,  4, 14, 11,  1,  2, 12, 15, 10,  9,  7,  5},
                {15,  2,  8,  0, 13, 14,  3,  9,  4,  6, 10,  1, 12, 11,  7,  5},
                { 7,  1, 14, 12,  2, 13,  6, 15, 11,  9,  5,  3,  8,  4, 10,  0}
        },
        {
                // S7盒
                { 4, 13, 11,  0,  2,  4, 15,  2,  9,  7,  6, 12,  5, 10,  3, 14},
                {11,  2,  4, 15,  0,  8,  3, 13, 12,  9,  7,  5, 10,  6, 14,  1},
                { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
                { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6}
        },
        {
                // S8盒
                {13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4},
                { 2, 14, 11,  0,  4, 13,  1,  6, 14,  9,  7,  3, 10,  5, 12, 15},
                { 8, 15, 13,  7,  1, 11,  5,  0,  3, 14,  9,  4, 12,  2, 10,  6},
                {12,  9,  0,  3,  5,  4,  8,  1, 10,  7,  6, 11, 13, 15,  2, 14}
        }
}; //S盒

const int P_box[32] = {
        16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25
}; //P盒

#endif //DES_DES_TABLE_H
