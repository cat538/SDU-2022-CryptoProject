//#include <openssl/sm3.h>
#include "LEA.h"
#include "../SM3/SM3.h"

vector<BYTE> * SM3LEA::SM3_LEA(){
	vector<BYTE>* new_msg = new vector<BYTE>();
	for(auto& x: orig) { new_msg -> push_back(x);} 
	int tail_len = (new_msg->size() + keylen) << 3; // 8倍
	//Extend a new block
	new_msg -> push_back(0x80);
	for(int i = (new_msg->size() + keylen + 8) % 64; i < 64 + 4; i++) 
		{ new_msg -> push_back(0x00); }
	//Extend length info
	for(int i = 3; i >= 0; i-- )
		{ new_msg -> push_back( (tail_len >> (i << 3)) & 0xff ); }

	//Init openssl SM3 instance
	SM3_CTX new_sig_ctx;
	SM3_Init(&new_sig_ctx);
	new_sig_ctx.Nl = (new_msg -> size() + keylen) << 3;
	for(int i = 0; i < 8; i ++){
		new_sig_ctx.h[i] = 0;
		for(int j = 0; j < 4; j ++){
			// eg: i = 0 : h[0] << 24 ; h[1] << 16; h[2] << 8; h[1] << 0;
			new_sig_ctx.h[i] |=  (orig_hash[(i << 2) + j] << ((3 - j) << 3)) ; 
		}
	}

	for(auto& x:add) new_msg -> push_back(x);
	char* buf = new char[add.size()];
	memcpy(&buf,&add,add.size());
	SM3_Update(&new_sig_ctx,buf,add.size());
	*new_sig = new BYTE[32];
	SM3_Final(*new_sig , &new_sig_ctx);
	delete [] buf;
	return new_msg;
}


/*SM3 Util*/
 
 int SM3sig(vector<BYTE> key, vector<BYTE> message, BYTE ** sig)
{
	*sig = new BYTE[128];
	SM3_CTX sig_ctx;
	SM3_Init(&sig_ctx);
	int len = key.size() + message.size();
	BYTE * buf = new BYTE[len];

	//Copy key and message into buf
	int i = 0;
	for(auto& x:key) buf[i++] = x;
	for(auto& x:message) buf[i++] = x;

	//Do SHa
	SM3_Update(&sig_ctx, buf, len);
	SM3_Final(*sig, &sig_ctx);
	delete [] buf;
	return 1;
}

bool VerifySM3(vector<BYTE> key, vector<BYTE> message, BYTE * test_sign)
{
	BYTE * gen_sig;
	SM3sig(key,message,&gen_sig);
	if(memcmp(gen_sig, test_sign, 32) == 0)
	{
		return true;
	}
	return false;
}


