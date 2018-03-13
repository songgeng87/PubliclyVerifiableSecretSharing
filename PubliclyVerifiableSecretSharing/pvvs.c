//
//  pvvs.c
//  PubliclyVerifiableSecretSharing
//
//  Created by 宋赓 on 2018/3/12.
//  Copyright © 2018年 宋赓. All rights reserved.
//
#include "uCurve.h"
#include "pvvs.h"
#include <stdlib.h>
#include "sha2.h"
void polynomial(uECC_word_t* coefficient, int degree, uECC_word_t input[uECC_N_WORDS],uECC_word_t output[uECC_N_WORDS]){
    uECC_word_t tmp[uECC_N_WORDS];
    
    int i=0;
    int j=0;
    
    vli_clear(output);
    
    for (i=0;i<degree;i++){
        vli_set(tmp,coefficient+i*uECC_N_WORDS);
        for(j=0;j<i;j++){
            vli_modMult_n(tmp, tmp, input);
        }
        vli_modAdd(output, output, tmp, curve_n);
    }
    return ;
}

void lagrange(int t, uint8_t* public_key_list,int index, uECC_word_t output[uECC_N_WORDS]){
    uECC_word_t tmp_j[uECC_N_WORDS];
    uECC_word_t tmp_i[uECC_N_WORDS];
    uECC_word_t tmp[uECC_N_WORDS];
    uint8_t digest[SHA256_DIGEST_LENGTH];
    int j=0;
    
    
    vli_clear(output);
    output[0] = 1;
    
    
    sha256_Raw(public_key_list+uECC_BYTES*2*index, uECC_BYTES*2, digest);
    vli_bytesToNative(tmp_i, digest);
    
    for (j=0;j<t;j++){
        if(j==index) continue;
        sha256_Raw(public_key_list+uECC_BYTES*2*j, uECC_BYTES*2, digest);
        vli_bytesToNative(tmp_j, digest);
        
        vli_modSub(tmp, tmp_j, tmp_i, curve_n);
        vli_modInv(tmp, tmp, curve_n);
        vli_modMult_n(tmp, tmp_j, tmp);
        
        vli_modMult_n(output, output, tmp);
    }
    
}
//Create a public/private key pair.
//public_key  - Will be filled in with the public key.
//private_key - Will be filled in with the private key.
//Returns 1 if the key pair was generated successfully, 0 if an error occurred.
int PVVS_make_key(uint8_t public_key[uECC_BYTES*2], uint8_t private_key[uECC_BYTES]){
    return uECC_make_key(public_key, private_key);
}

//distribution the secret as a t-n scheme
//output: the real secret G^{secret}
//input: secret: the random number
//       public_key_list: n public keys to be shared
//       dis_secret: the distribution of the secret to the public key
void distribution(int t, int n, uint8_t secret[uECC_BYTES], uint8_t* public_key_list, uint8_t* public_C,uint8_t* dis_secret, uint8_t real_secret[uECC_BYTES*2]){
    uECC_word_t* coefficient;
    uECC_word_t tmp[uECC_N_WORDS];
    uECC_word_t poly_i[uECC_N_WORDS];
    int i;
    uint8_t urn[uECC_BYTES];
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uECC_word_t random[uECC_N_WORDS];
    EccPoint C;
    EccPoint X;
    
    
    coefficient = (uECC_word_t *)malloc(sizeof(uECC_word_t)*uECC_N_WORDS*t);
    vli_bytesToNative(tmp, secret);
    vli_set(coefficient, tmp);
    
    EccPoint_mult(&C, &curve_G, tmp,0, vli_numBits(tmp, uECC_N_WORDS));
    vli_nativeToBytes(real_secret, C.x);
    vli_nativeToBytes(real_secret+uECC_BYTES, C.y);
    
    EccPoint_mult(&C, &curve_P, tmp,0, vli_numBits(tmp, uECC_N_WORDS));
    vli_nativeToBytes(public_C , C.x);
    vli_nativeToBytes(public_C + uECC_BYTES, C.y);
    
    for(i=1;i<t;i++){
        default_RNG(urn,sizeof(urn));
        vli_bytesToNative(random, urn);
        vli_set(coefficient+i*uECC_N_WORDS, random);
        EccPoint_mult(&C, &curve_P, random,0, vli_numBits(random, uECC_N_WORDS));
        vli_nativeToBytes(public_C + i*uECC_BYTES, C.x);
        vli_nativeToBytes(public_C + i*uECC_BYTES + uECC_BYTES, C.y);
    }
    
    for(i=0;i<n;i++){
        sha256_Raw(public_key_list+uECC_BYTES*2*i, uECC_BYTES*2, digest);
        vli_bytesToNative(tmp, digest);
        
        polynomial(coefficient, t, tmp,poly_i);
        
        EccPoint_mult(&X, &curve_P, poly_i,0, vli_numBits(poly_i, uECC_N_WORDS));
        
        vli_nativeToBytes(dis_secret+uECC_BYTES*4*i, X.x);
        vli_nativeToBytes(dis_secret+uECC_BYTES*4*i+uECC_BYTES, X.y);
        
        vli_bytesToNative(C.x, public_key_list+uECC_BYTES*2*i);
        vli_bytesToNative(C.y, public_key_list+uECC_BYTES*2*i+uECC_BYTES);
        
        EccPoint_mult(&X, &C, poly_i,0, vli_numBits(poly_i, uECC_N_WORDS));
        
        vli_nativeToBytes(dis_secret+uECC_BYTES*4*i+uECC_BYTES*2, X.x);
        vli_nativeToBytes(dis_secret+uECC_BYTES*4*i+uECC_BYTES*3, X.y);
    }

    free(coefficient);
    return ;
}

//check the dis_secret to the i-th public key
//Returns 1 if the dis_secret is right, 0 if an error occurred.
int verification(int i, uint8_t public_key[uECC_BYTES*2], uint8_t dis_secret[uECC_BYTES*4]){
    return 1;
}

//decryption the dis_secret with the private key to de_dis_secret
int decryption(uint8_t private_key[uECC_BYTES], uint8_t dis_secret[uECC_BYTES*4], uint8_t de_dis_secret[uECC_BYTES*2]){
    uECC_word_t tmp[uECC_N_WORDS];
    EccPoint Y;
    EccPoint X;
    
    vli_bytesToNative(tmp, private_key);
    
    vli_bytesToNative(Y.x, dis_secret+2*uECC_BYTES);
    vli_bytesToNative(Y.y, dis_secret+3*uECC_BYTES);
    
    vli_modInv(tmp, tmp, curve_n);
    EccPoint_mult(&X, &Y, tmp,0, vli_numBits(tmp, uECC_N_WORDS));
    
    vli_nativeToBytes(de_dis_secret, X.x);
    vli_nativeToBytes(de_dis_secret+uECC_BYTES, X.y);
    return 1;
}

// reconstructe the secret from t decrypted de_dis_secret
// output: the real secret G^{secret}
// input: n_list with t index
//        de_dis_secret  t de_dis_secret
void pooling(int t, uint8_t* public_key_list,uint8_t* de_dis_secret, uint8_t pool_share[uECC_BYTES*2]){
    //lagrange(int t, uint8_t* public_key_list,int index, uECC_word_t output[uECC_N_WORDS])
    int j;
    EccPoint de_dis;
    EccPoint X;
    EccPoint output;
    uECC_word_t tmp[uECC_N_WORDS];
    
    lagrange(t, public_key_list, 0, tmp);
    vli_bytesToNative(de_dis.x, de_dis_secret);
    vli_bytesToNative(de_dis.y, de_dis_secret+uECC_BYTES);
    EccPoint_mult(&output, &de_dis, tmp,0, vli_numBits(tmp, uECC_N_WORDS));
    
    for(j=1;j<t;j++){
        lagrange(t, public_key_list, j, tmp);
        vli_bytesToNative(de_dis.x, de_dis_secret+uECC_BYTES*2*j);
        vli_bytesToNative(de_dis.y, de_dis_secret+uECC_BYTES*2*j+uECC_BYTES);
        EccPoint_mult(&X, &de_dis, tmp,0, vli_numBits(tmp, uECC_N_WORDS));
        EccPoint_add(output.x, output.y, X.x, X.y);
        //XYcZ_addC(X.x, X.y, output.x, output.y);
    }
    vli_nativeToBytes(pool_share, output.x);
    vli_nativeToBytes(pool_share+uECC_BYTES, output.y);
    return ;
}

void vli_out(uint8_t *c,int t){
    int i=0;
    printf("==================\n");
    for(i=0;i<t;i++){
        printf("%02x",c[i]);
        if(i==31) printf("\n");
    }
    printf("\n======== END ==========\n");
}
