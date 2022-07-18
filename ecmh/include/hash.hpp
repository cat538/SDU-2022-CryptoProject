
#include "openssl.inc"
#include "std.inc"
class Hash{
private:
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md = NULL;
    size_t digest_size;
public:
    Hash(){
        md = EVP_get_digestbyname("sha256");
        digest_size = EVP_MD_get_size(md);
    }
    Hash(std::string hashName) {
        md = EVP_MD_fetch(NULL, hashName.c_str(), NULL);
        digest_size = EVP_MD_get_size(md);
    }
    ~Hash(){}
    
    std::string Digest(const std::string& mess){
        md_ctx = EVP_MD_CTX_new();
        if(md == NULL || md_ctx == NULL) {std::cout << "Hash Generate Error\n"; exit(1);}
        unsigned char hash[digest_size];
        unsigned int md_len, i;
        EVP_DigestInit_ex2(md_ctx, md, NULL);
        EVP_DigestUpdate(md_ctx, mess.data(), mess.size());
        EVP_DigestFinal_ex(md_ctx, hash, &md_len);
        EVP_MD_CTX_free(md_ctx);
        //for(int i = 0; i < 32; i++) printf("%02x",hash[i]); printf("\n");
        return std::string(reinterpret_cast<char*>(hash), digest_size);
    }

    size_t DigestSize(){return digest_size;};

};
