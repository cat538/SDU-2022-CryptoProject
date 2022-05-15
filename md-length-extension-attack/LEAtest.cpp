
#include "LEA.h"
#include "util.h"

void LEAtest(){
	string msg = "name=escolhido&role=user";
	string add = "&role=admin";
	string key = "abc";
	// MESSAGE
	vector<BYTE> vmessage = String2Vector((BYTE*) msg.c_str());
	//ADD);
	vector<BYTE> vadd = String2Vector((BYTE*) add.c_str());
	//vector<BYTE> vkey = String2Vector((BYTE*) key.c_str());
	vector<BYTE> vkey = GenerateRandomString(); //Generate random key
	int keylen = vkey.size();
	//printf_BYTE(vadd);

	BYTE * orig_sig;
	BYTE * add_sig;
	
printf("Key len: %d\n", keylen);
printf("Key:");
print_BYTE2string(&vkey);

printf("----------------- SHA256LEA TEST -----------------\n");

	printf(" >> Original Message\n   ");
	print_BYTE2string(&vmessage);
	printf("\n >> Original Signature\n   ");
	SHA256(vkey,vmessage,&orig_sig);
	printf_BYTE(orig_sig,32);
	if(VerifySHA256(vkey,vmessage,orig_sig)) printf("PASS\n" );
	else printf("WRONG\n");


	printf("\n >> Appended Message\n   ");
	SHA256LEA* SHA256_attack = new SHA256LEA(vmessage,keylen,orig_sig,vadd,&add_sig);
	vector<BYTE> * app_msg =  SHA256_attack -> SHA256_LEA();
	print_BYTE2string(app_msg);
	printf("\n >> Appended Signature\n   ");
	printf_BYTE(add_sig,32);
	if(VerifySHA256(vkey,*app_msg,add_sig)) printf("PASS\n" );
	else printf("WRONG\n");



printf("\n----------------- SM3LEA TEST -----------------\n");

	printf(" >> Original Message\n   ");
	print_BYTE2string(&vmessage);
	printf("\n >> Original Signature\n   ");
	SM3sig(vkey,vmessage,&orig_sig);
	printf_BYTE(orig_sig,32);
	if(VerifySM3(vkey,vmessage,orig_sig)) printf("PASS\n" );
	else printf("WRONG\n");


	printf("\n >> Appended Message\n   ");
	SM3LEA* SM3_attack = new SM3LEA(vmessage,keylen,orig_sig,vadd,&add_sig);
	app_msg =  SM3_attack -> SM3_LEA();
	print_BYTE2string(app_msg);
	printf("\n >> Appended Signature\n   ");
	printf_BYTE(add_sig,32);
	if(VerifySM3(vkey,*app_msg,add_sig)) printf("PASS\n" );
	else printf("WRONG\n");

}




int main(){
	LEAtest();
}