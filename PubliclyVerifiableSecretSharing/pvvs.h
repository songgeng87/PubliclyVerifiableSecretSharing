//
//  pvvs.h
//  PubliclyVerifiableSecretSharing
//
//  Created by 宋赓 on 2018/3/12.
//  Copyright © 2018年 宋赓. All rights reserved.
//

#ifndef pvvs_h
#define pvvs_h

#include <stdio.h>
#include "uECC.h"

//生成一对公私钥对
//Outputs:
//public_key  - Will be filled in with the public key.
//private_key - Will be filled in with the private key.
//Returns 1 if the key pair was generated successfully, 0 if an error occurred.
int PVVS_make_key(uint8_t public_key[uECC_BYTES*2], uint8_t private_key[uECC_BYTES]);


//按t-n方案对secret进行分割
//实际的秘密是G^{secret}，存储在real_secret中，长度uECC_BYTES*2
//需要n组公钥，共计长度uECC_BYTES*2*n
//输出验证时需要的t组公共参数C，存储在public_C中，共计长度uECC_BYTES*2*t
//分发给n个部分的秘密存储在dis_secret中，每个部分长度uECC_BYTES*4，共计长度uECC_BYTES*4*n
void distribution(int t, int n, uint8_t secret[uECC_BYTES], uint8_t* public_key_list, uint8_t* public_C,uint8_t* dis_secret, uint8_t real_secret[uECC_BYTES*2]);

//todo
//验证每个部分是否正确
int verification(int i, uint8_t public_key[uECC_BYTES*2], uint8_t dis_secret[uECC_BYTES*4]);

//每个部分在收到秘密后使用私钥进行解密，获得的部分秘密存储在de_dis_secret，共计长度uECC_BYTES*2
int decryption(uint8_t private_key[uECC_BYTES], uint8_t dis_secret[uECC_BYTES*4], uint8_t de_dis_secret[uECC_BYTES*2]);

//使用t个部分秘密还原原来的秘密，
//需要输入公钥及其对应的部分秘密，
//还原的秘密存储在pool_share中。
void pooling(int t, uint8_t* public_key_list,uint8_t* de_dis_secret, uint8_t pool_share[uECC_BYTES*2]);

void vli_out(uint8_t *c,int t);
#endif /* pvvs_h */
