#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include "create_key.h"
#include "sm2_sign.h"

using namespace std;


int main(int argc, char** argv)
{
	int error_code;
	unsigned char msg[] = { "message digest" };
	unsigned int msg_len = (unsigned int)(strlen((char*)msg));
	unsigned char user_id[] = { "1234567812345678" };
	unsigned int user_id_len = (unsigned int)(strlen((char*)user_id));
	SM2_KEY_PAIR key_pair;
	SM2_SIGNATURE_STRUCT sm2_sig;
	int i;

	if (error_code = sm2_create_key_pair(&key_pair))	//生成公私钥对
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");
	printf("Private key:\n");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
		printf("0x%x ", key_pair.pri_key[i]);

	printf("\n\n");
	printf("Public key:\n");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x ", key_pair.pub_key[i]);
	}
	printf("\n\n");

	printf("/*********************************************************/\n");
	if (error_code = sm2_sign_data(msg, msg_len, user_id, user_id_len, key_pair.pub_key, key_pair.pri_key, &sm2_sig))
	{
		printf("Create SM2 signature failed!\n");
		return error_code;
	}
	printf("Create SM2 signature succeeded!\n");
	printf("SM2 signature:\n");
	printf("r coordinate:\n");
	for (i = 0; i < sizeof(sm2_sig.r_coordinate); i++)
	{
		printf("0x%x ", sm2_sig.r_coordinate[i]);
	}
	printf("\n");
	printf("s coordinate:\n");
	for (i = 0; i < sizeof(sm2_sig.s_coordinate); i++)
	{
		printf("0x%x ", sm2_sig.s_coordinate[i]);
	}
	printf("\n\n");

	if (error_code = sm2_verify_sig(msg, msg_len, user_id, user_id_len, key_pair.pub_key, &sm2_sig))
	{
		printf("Verify SM2 signature failed!\n");
		return error_code;
	}
	printf("Verify SM2 signature succeeded!\n");



	return 0;
}