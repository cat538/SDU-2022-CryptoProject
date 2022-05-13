#include <openssl/rsa.h>
#include <iostream>
#include <string>

using namespace std;


RSA* getRSA(long rsaE,int rsaSize)
{
	// 创建一个RSA结构体
	RSA *rsa = RSA_new();
	// 判断是否创建成功
	if(NULL == rsa)
	{
		return NULL;
	}

	// 新建一个大数的结构体
	BIGNUM *eNum = BN_new();
	// 判断创建成功
	if(NULL == eNum)
	{
		return NULL;
	}
	// 通过BN_set_word来设置RSA中的E
	if(!BN_set_word(eNum,rsaE))
	{
		return NULL;
	}
	// 通过RSA_generate_key_ex()来对rsa进行初始化
	if(!RSA_generate_key_ex(rsa,rsaSize,eNum,NULL))
	{
		return NULL;
	}
	// 释放eNum指针
	BN_free(eNum);
	// 返回rsa指针
	return rsa;
}

int main()
{
	// 由e = 65537生成模数为1024的rsa指针
	RSA *rsa = getRSA(65537,1024);
	// 需要加密的明文
	unsigned char chIn[] = "Hello world!";
	// 保存密文
	unsigned char chOut[2048] = "";
	// 保存密文解密之后的结果
	unsigned char chMsg[1024] = "";

	//打印明文
	cout << chIn << endl;
	//公钥加密明文生成密文
	printf("%d\n",RSA_public_encrypt(strlen((const char*)chIn)+1,chIn,chOut,rsa,RSA_PKCS1_PADDING));	
	//打印密文
	cout << chOut << endl;	
	//私钥解密密文
	printf("%d\n",RSA_private_decrypt(128,chOut,chMsg,rsa,RSA_PKCS1_PADDING));	
	//打印解密后的密文
	cout << chMsg << endl;	

	//用于签名和验签：
	printf("%d\n",RSA_private_encrypt(strlen((const char*)chIn)+1,chIn,chOut,rsa,RSA_PKCS1_PADDING));	//私钥加密明文生成密文
	//打印密文
	cout << chOut << endl;
	//公钥解密
	printf("%d\n",RSA_public_decrypt(128,chOut,chMsg,rsa,RSA_PKCS1_PADDING));	
	//打印解密后的密文
	cout << chMsg << endl;	

	RSA_free(rsa);	//释放rsa结构体内存

	system("pause");
	return 0;
}
