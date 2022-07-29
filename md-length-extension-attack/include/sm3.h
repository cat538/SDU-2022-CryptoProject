
#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64
#define SM3_CBLOCK		(SM3_BLOCK_SIZE)
#define SM3_LBLOCK      (SM3_CBLOCK/4)
#define SM3_LONG unsigned int
#define DATA_ORDER_IS_BIG_ENDIAN
#include <string.h>

extern "C" {

typedef struct {
	SM3_LONG h[8];
	SM3_LONG Nl,Nh;
	SM3_LONG data[SM3_LBLOCK];
	unsigned int num;
} SM3_CTX;


int SM3_Init(SM3_CTX *c);
int SM3_Update(SM3_CTX *c,  const void *data, size_t len);
int SM3_Final(unsigned char *md, SM3_CTX *c);
void SM3_Transform(SM3_CTX *c, const unsigned char *data);
void SM3(const unsigned char *msg, size_t msglen,
    unsigned char *dgst);

}
/*
typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;  */
