//
//  main.c

//  PubliclyVerifiableSecretSharing


//  an implemention of the scheme in cryto99 based on ecc
//

//  Created by 宋赓 on 2018/3/10.
//  Copyright © 2018年 宋赓. All rights reserved.
//

#include <stdio.h>
#include "uECC.h"
#include "uCurve.h"
#include "pvvs.h"


int main(int argc, const char * argv[]) {
    // test t=10,n=20;  test 6--15
    //int PVVS_make_key(uint8_t public_key[uECC_BYTES*2], uint8_t private_key[uECC_BYTES]);
    //void distribution(int t, int n, uint8_t secret[uECC_BYTES], uint8_t* public_key_list, uint8_t* public_C,uint8_t* dis_secret, uint8_t real_secret[uECC_BYTES*2]);
    //int decryption(uint8_t private_key[uECC_BYTES], uint8_t dis_secret[uECC_BYTES*4], uint8_t de_dis_secret[uECC_BYTES*2]);
    //void pooling(int t, uint8_t* public_key_list,uint8_t* de_dis_secret, uint8_t pool_share[uECC_BYTES*2]);
    int i=0;
    int t = 16;
    uint8_t public_key_list[uECC_BYTES*2*20];
    uint8_t private_key_list[uECC_BYTES*20];
    uint8_t secret[uECC_BYTES] = {0x0C,0x28,0xFC,0xA3,0x86,0xC7,0xA2,0x27,0x60,0x0B,0x2F,0xE5,0x0B,0x7C,0xAE,0x11,0xEC,0x86,0xD3,0xBF,0x1F,0xBE,0x47,0x1B,0xE8,0x98,0x27,0xE1,0x9D,0x72,0xAA,0x1D};
    
    uint8_t real_secret[uECC_BYTES*2];
    
    uint8_t public_C[uECC_BYTES*2*10];
    
    uint8_t dis_secret[uECC_BYTES*4*20];
    
    uint8_t de_dis_secret[uECC_BYTES*2*20];
    
    uint8_t pool_share[uECC_BYTES*2];
    // 生成20组公钥
    for(i=0;i<20;i++){
        PVVS_make_key(public_key_list+uECC_BYTES*2*i,private_key_list+uECC_BYTES*i);
    }
    
    // 按16-20进行分割  t=16
    distribution(t, 20, secret, public_key_list, public_C, dis_secret, real_secret);
    
    // 输出实际的秘密
    vli_out(real_secret, 64);
    
    //执行20次解密
    for(i=0;i<20;i++){
        decryption(private_key_list+uECC_BYTES*i, dis_secret+uECC_BYTES*4*i, de_dis_secret+uECC_BYTES*2*i);
    }
    //利用16个部分秘密还原真实秘密
    pooling(t, public_key_list+uECC_BYTES*2*0, de_dis_secret+uECC_BYTES*2*0, pool_share);
    //输出还原的秘密
    vli_out(pool_share, 64);
    
    return 0;
}
