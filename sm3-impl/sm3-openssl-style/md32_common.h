
# define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))


#  define HOST_c2l(c,l)  (l =(((unsigned long)(*((c)++)))<<24),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))    )           )
#  define HOST_l2c(l,c)  (*((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)    )&0xff),      \
                         l)


int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len)
{
    const unsigned char *data = (unsigned char *)data_;
    unsigned char *p;
    HASH_LONG l;
    size_t n;

    if (len == 0)
        return 1;

    l = (c->Nl + (((HASH_LONG) len) << 3)) & 0xffffffffUL;
    /*
     * 95-05-24 eay Fixed a bug with the overflow handling, thanks to Wei Dai
     * <weidai@eskimo.com> for pointing it out.
     */
    if (l < c->Nl)              /* overflow */
        c->Nh++;
    c->Nh += (HASH_LONG) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    c->Nl = l;

    n = c->num;
    if (n != 0) {
        p = (unsigned char *)c->data;

        if (len >= HASH_CBLOCK || len + n >= HASH_CBLOCK) {
            memcpy(p + n, data, HASH_CBLOCK - n);
            HASH_BLOCK_DATA_ORDER(c, p, 1);
            n = HASH_CBLOCK - n;
            data += n;
            len -= n;
            c->num = 0;
            /*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             */
            memset(p, 0, HASH_CBLOCK); /* keep it zeroed */
        } else {
            memcpy(p + n, data, len);
            c->num += (unsigned int)len;
            return 1;
        }
    }

    n = len / HASH_CBLOCK;
    if (n > 0) {
        HASH_BLOCK_DATA_ORDER(c, data, n);
        n *= HASH_CBLOCK;
        data += n;
        len -= n;
    }

    if (len != 0) {
        p = (unsigned char *)c->data;
        c->num = (unsigned int)len;
        memcpy(p, data, len);
    }
    return 1;
}

void HASH_TRANSFORM(HASH_CTX *c, const unsigned char *data)
{
    HASH_BLOCK_DATA_ORDER(c, data, 1);
}

int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
    unsigned char *p = (unsigned char *)c->data;
    size_t n = c->num;

    p[n] = 0x80;                /* there is always room for one */
    n++;

    if (n > (HASH_CBLOCK - 8)) {
        memset(p + n, 0, HASH_CBLOCK - n);
        n = 0;
        HASH_BLOCK_DATA_ORDER(c, p, 1);
    }
    memset(p + n, 0, HASH_CBLOCK - 8 - n);

    p += HASH_CBLOCK - 8;
    (void)HOST_l2c(c->Nh, p);
    (void)HOST_l2c(c->Nl, p);
    
     p -= HASH_CBLOCK;
    HASH_BLOCK_DATA_ORDER(c, p, 1);
    c->num = 0;
    HASH_MAKE_STRING(c, md);

    return 1;
}