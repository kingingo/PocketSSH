#include "dh.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>

dh_ctx *dh_init(bn_t*,bn_t*);
bn_t *dh_calc(dh_ctx*,bn_t*);

/*
void printV(ul_t v){
    for(int j=0; j < BN_PART_BITS; j++){
       printf("%u",((v >> j) & 1));
    }
}


void main(void){
    bn_t *prime = bn_from_bin(bn_alloc(256),GROUP_14,256);
    bn_t *g = bn_from_bin(bn_alloc(256),"\x02",1);
    bn_t* F = bn_from_bin(bn_alloc(256),"",256);
    bn_t* e = bn_from_bin(bn_alloc(256),"",256);
    bn_t* E = bn_from_bin(bn_alloc(256),"",256);

    bn_t* K = bn_alloc(256);
    bn_pow_mod(K,F,e,prime);
    bn_print(stdout,"K:",K,"\n");
    //H = hash(V_C || V_S || I_C || I_S || K_S || e || F || K)
    char V_C[] = "SSH-2.0-Rafiq";
    char V_S[] = "SSH-2.0-OpenSSH_8.7";

    BYTE data[1];
    BYTE buf[SHA256_BLOCK_SIZE];

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, strlen(data));
    sha256_final(&ctx, buf);
}
void main(void) {
    BYTE buf[SHA256_BLOCK_SIZE];
    bn_t *prime = bn_from_bin(bn_alloc(256),GROUP_14,256);
    bn_t *g = bn_from_bin(bn_alloc(256),"\x02",1);

    dh_ctx *dh_ctx = dh_init(g,prime);
    bn_print(stdout,"X:",dh_ctx->X,"\n");
   printf("DO MPINT\n");
    uint8_t *ptr = calloc(sizeof(uint8_t),256);
    bn_to_ptr(dh_ctx->X,&ptr);
   printf("MPINT: %s\n",ptr);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, X_mpint, strlen(X_mpint));
    sha256_final(&ctx, buf);
    
    
   printf("\n");
   printf("BUF:");
    for(int i = 0; i < SHA256_BLOCK_SIZE; i++)
       printf("%02X",buf[i]);
   printf("\n");
}

void main(void){
    bn_t *prime = bn_from_bin(bn_alloc(256),GROUP_14,256);
    bn_t *g = bn_from_bin(bn_alloc(256),"\x02",1);

    dh_ctx *alice = dh_init(g,prime);
    dh_ctx *bob = dh_init(g,prime);

    bn_t* k_alice = dh_calc(alice, bob->X);
    bn_t* k_bob = dh_calc(bob, alice->X);

    bn_print(stdout,"ALICE K:",k_alice,"\n");
    bn_print(stdout,"BOB K:",k_bob,"\n");
   printf("=> %s\n",(bn_cmp(k_alice,k_bob)==BN_CMP_E ? "CORRECT" : "WRONG"));
    
}

void main(void){
    
    
    //CLIENT_PUB:
    //00 
    //1e 44 cd 6f d2 4f ed be 17 21 1e d5 76 74 df 75 92 82 73 83 34 e8 17 be 1c f0 b4 79 bf c8 61 18 
    //20 65 8b d9 38 4b fa 06 5f 4a c2 3d 4b e0 e7 b0 f2 0c 0a 1d c0 66 b3 63 02 96 ef 1d 5d 28 8e dd 
    //6f f0 bc d8 63 f1 6f 59 04 a4 0b 5f 0c 3b a2 e6 ae 64 1b 45 7b 62 71 09 fc 13 29 dc 56 b2 e2 d1 
    //a1 02 db 96 d8 7f db bd 6f 1f 04 8d ef 20 82 32 39 ed b2 61 5e c3 0b 97 6a c5 6c 3b 9a 69 ba 3c 
    //69 8a f5 63 61 ab 68 1e 15 bf 8e 07 5d 57 ab 1b cc 51 51 a9 c4 a0 cd 5c aa 01 34 36 aa 2f f1 d1 
    //c8 ab d5 bc ad 9e 7e 36 89 33 c8 44 ff 39 50 e6 b5 d0 29 39 cb de e8 23 90 00 40 e0 92 7c 17 8d 
    //73 45 59 0b 03 e6 3f 6d 19 50 42 c4 45 39 57 a1 69 5e 42 04 cf 0c 8e 2d e2 1e 9a 1b 48 32 9d e6 
    //a5 dd fe f8 27 46 54 93 90 f6 b2 fc 71 44 ae 18 ab b9 f7 d7 c9 ae 18 02 76 ca d3 a6 1f 95 62 e7
   
    
    dh_ctx *context;
    context = (dh_ctx*)calloc(sizeof(dh_ctx),1);
    bn_t* output_shared_secret = bn_from_bin(bn_alloc(256),"\x67\x1f\x56\x2c\xc2\x1b\x13\x5f\xa7\x80\x99\x4b\x9d\xb3\xd4\x03\xe2\x22\x09\x8d\x81\x9f\xba\x46\xff\xc6\x95\x6e\x25\xe1\xb0\x47\xd4\xba\xdc\x86\xaf\x38\xc5\x69\xe8\x96\x29\x06\x07\x27\xf0\xc8\xca\xcc\x9d\x33\x49\x21\x2d\x16\x6c\xfc\x7d\x18\x98\x3c\x75\x31\x3c\x26\xb8\xd9\x4b\x7f\xcd\x80\x6e\xa2\x75\x50\xaf\x9e\xde\x06\xf1\xa2\x7b\x18\xa4\xa7\x30\x3d\x23\x95\x1b\x74\x50\x3a\xe7\x8f\x92\xb2\x68\x44\x21\x16\x23\x86\x92\xeb\xd1\x8a\xbc\xa5\x63\x48\xbb\xcd\x6d\x47\x1e\xad\x79\x08\xb5\x6e\xf7\x26\xef\x7b\xd0\x87\xe3\x9c\x58\x19\x2a\x12\x0e\x64\xe0\xa5\x6f\x76\x5f\xbd\xe7\x9f\xed\x27\x81\x29\x4b\x77\x82\xb1\x02\x9d\xbf\xd9\x4f\x8a\x1d\x20\xe4\x38\x0c\x0f\x0d\x49\xe0\x8a\x50\x93\xe7\x41\x9d\x43\x46\x31\xa4\x4d\x1d\xc3\xba\x3f\xb3\xfa\x09\x75\x2f\xb5\xac\xb0\x8c\xaa\xd8\x40\x9d\x5f\x6a\xb4\x31\x14\x48\x12\xe3\xf3\x8a\x8e\x7e\xf0\xd9\x90\x73\xc0\x9b\x65\x90\x73\x08\xd9\x00\x19\x46\x85\xee\x61\xd7\x24\x1e\x2f\xac\x87\x8c\x1a\x80\x44\x7b\x0a\x31\xd3\x5a\xc4\x60\xc3\x55\x3f\x07\xd3\x4a\x7f\x4a\xb4\xf2\x86\x4e\x9e\x36\x3d",256);
    
    context->prime = bn_from_bin(bn_alloc(256),GROUP_14,256);
    context->generator = bn_from_bin(bn_alloc(256),"\x02",1);
    context->x = bn_from_bin(bn_alloc(256),"\x8a\xf1\x05\x43\xb2\x46\xae\xaf\x58\x24\xbf\x91\xa8\x25\x54\x35\x01\x48\xbc\x11\x66\x4b\x18\x8a\xcb\x44\xa0\xd9\x2f\x13\x03\x52\xe4\xd1\x75\xec\xbf\x8f\x61\xd9\xdd\x7f\xa6\x0d\x4c\xd3\xf0\xf1\xfd\x89\x31\xfb\xb9\x59\x4b\xcc\x40\x07\xfe\x6c\xab\x3f\xd7\xa5\xe4\xb0\x6b\x79\xb1\x12\x9e\xfd\x00\xb2\x48\xdc\xa6\x02\x4f\x73\x4f\x12\xcb\xc4\xc8\x64\xca\xef\x2f\x50\x05\x85\xd4\x3f\x39\x7c\x7d\x58\x63\x3a\xba\x24\x0e\x1b\xc8\xfe\xfb\x94\x5a\x97\xb9\xf8\x84\xef\xd1\xa1\xcb\x88\x7b\x84\xce\x63\x8a\x30\x07\x07\x72\xd0\x97\x0e\x78\xf4\xa9\x72\xf8\x10\xb6\xca\xde\x63\x28\x9e\x46\x0f\x76\xbf\x8f\x55\xe7\x79\xdd\x65\x03\x55\xc5\x84\xca\x98\xa9\x47\x95\xd9\x94\x3a\xa0\x02\xd5\x6a\x30\x5b\x34\x13\x36\x0c\x74\xdb\x34\xad\x9b\x83\x7f\x82\x67\x26\xb1\x2f\x36\xd9\x47\x0d\xc6\x90\x74\x15\xe7\x47\x58\x53\x4c\xb3\x87\x51\x82\xd9\xb4\xfd\xc4\xc1\x94\x6e\x34\x11\x64\x49\xc9\xe8\x83\x5a\x14\x88\xc0\x88\xae\x82\x64\x6d\xc9\xd5\x08\x16\xf2\x88\x01\x73\x14\x94\xeb\x94\x8a\x76\x3a\xa8\x4c\x3f\x1f\x39\x24\x14\x60\xda\xe7\x1a\x81\x10\xad\x78",256);
    context->X = bn_alloc(context->prime->n);
    bn_pow_mod(context->X,context->generator,context->x,context->prime);

    bn_print_blocks(stdout,"x:",context->x,"\n\n");
    bn_print_blocks(stdout,"CLIENT_PUB = X:",context->X,"\n\n");

    bn_t* D = bn_from_bin(bn_alloc(256),"\x67\x3f\xcd\x04\xfa\x48\x10\x5d\x18\x95\x04\x76\x94\xea\x2b\xca\xa0\x5b\x9a\x6b\x01\x08\xc6\x37\x9e\x90\xaa\xd6\x65\x34\xa5\xd3\x75\x3b\x86\x4a\x74\xac\x7a\x08\x0a\x3e\xc7\xef\xed\x2c\xb6\xbe\x92\xeb\x2a\x97\x4e\xa2\x02\x4c\x79\xa8\x38\x18\x3e\x09\x29\x45\x42\xe4\x03\x75\xe9\xb8\x29\x15\xee\x93\x95\xc1\xf2\xc4\x83\xd1\x63\x7a\xf8\x7a\xd5\xa9\x04\xfb\xec\xd7\x29\xe1\x1c\x3e\xe0\xf7\x04\xe8\xbe\xcf\x42\x62\xd3\xff\xbf\xe4\x1a\xb9\xed\x5e\x43\x1d\x04\xc0\xff\xd5\xf4\x65\xbc\x0f\x64\x78\x40\x89\x6a\xe5\x7d\x6e\x49\xb0\xbe\x9e\xc0\xe6\x9a\x2c\x71\xad\xda\xa4\xb3\x85\xd0\x51\xb0\x8a\x70\x38\x87\x0b\x9b\x43\x6a\x4c\xaa\x81\x4f\xae\xc0\x55\xc1\x71\x54\xb0\xbb\x52\x99\x5c\x19\xc0\x4c\x3d\xdf\x90\x26\x19\x8a\xd0\x47\x3b\x55\x05\xce\xa1\x32\x06\x72\xbd\xe1\x3c\x31\x25\x13\x66\xd8\x82\xbd\x3b\xdb\xf9\x64\x6b\xfe\x62\xcf\x51\x86\x1a\xf6\x4a\x65\x4e\x3d\xce\xec\x58\x1c\x3b\xd2\xa4\x6e\x8f\x69\x47\x77\xd3\xf6\x0c\x50\x19\x75\x32\x1c\xa4\x2c\x40\x1e\xdc\xa4\x84\xf3\x73\x75\xab\xca\xe6\x30\xcd\x68\x5b\x4b\x2f\xee\x1c\x56\xe2",256);
    
    bn_print_blocks(stdout,"SERRVER_PUB = D:",D,"\n\n");
    bn_t* secret = dh_calc(context,D);
    bn_print_blocks(stdout,"SECRET:",secret,"\n\n");
    bn_print_blocks(stdout,"OUTPUT_SECRET:",output_shared_secret,"\n\n");

   printf("%s\n", (bn_cmp(secret, output_shared_secret) == BN_CMP_E ? "SUCCESSFULL" : "WRONG!!"));
}*/

dh_ctx *dh_init(bn_t *G,bn_t *p){
    dh_ctx *context;

    if((context = (dh_ctx*)calloc(sizeof(dh_ctx),1)) == NULL)
        return NULL;

    context->generator = G;
    context->prime = p;
    context->x = bn_alloc(context->prime->n);
    bn_rand_range(context->x, 2, context->prime, 2);
    context->X = bn_alloc(context->prime->n);
    bn_pow_mod(context->X,context->generator,context->x,context->prime);
    return context;
}

bn_t * dh_calc(dh_ctx *context,bn_t *D){
    int i;
    bn_t *C = bn_alloc(context->prime->n);
    /*bn_t *K = ;

    i = K->n;
    for(;i <= 0; i--)
        if(*(K->p+i) != 0x00)
            break;
    
    bn_t *K1 = bn_alloc(i);
    memcpy(K1->p, K->p + (K->n-i), i);
    free(K);*/
    return bn_pow_mod(C,D,context->x,context->prime);
}