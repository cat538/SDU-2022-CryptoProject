#include <iostream>
#include <vector>
#include <unistd.h>
#include <random>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
using namespace std;

typedef unsigned char BYTE;



// void DigestToRaw(string hash, unsigned char * raw);
// vector<BYTE> String2Vector(BYTE* str);
// vector<BYTE> * GenerateRandomString();
// void print_BYTE2string(vector<BYTE> *s,int size = 0);
// void print_BYTE2string(BYTE* str,int size = 0);
// void printf_BYTE(vector<BYTE> *s,int size = 0);
// void printf_BYTE(BYTE* str,int size = 0);

int SHA256(vector<BYTE> key, vector<BYTE> message, BYTE ** sig);
bool VerifySHA256(vector<BYTE> key, vector<BYTE> message, BYTE * signature);
 int SM3sig(vector<BYTE> key, vector<BYTE> message, BYTE ** sig);
 bool VerifySM3(vector<BYTE> key, vector<BYTE> message, BYTE * test_sign);
void LEAtest();


class LEA{
public:
	vector<BYTE> orig;
	int keylen;
	BYTE * orig_hash;
	vector<BYTE> add;
	BYTE ** new_sig;
	LEA(vector<BYTE> _orig = vector<BYTE>(), int _keylen = 32, 
		BYTE * _orig_hash = nullptr, vector<BYTE> _add =vector<BYTE>(),
		BYTE ** _new_sig = nullptr)
	{
		orig = _orig;
		keylen = _keylen;
		orig_hash = _orig_hash;
		add = _add;
		new_sig = _new_sig;
	}
};

class SM3LEA : public LEA{
public:
	SM3LEA(vector<BYTE> _orig = vector<BYTE>(), int _keylen = 32, 
		BYTE * _orig_hash = nullptr, vector<BYTE> _add =vector<BYTE>(),
		BYTE ** _new_sig = nullptr):LEA(_orig,_keylen,_orig_hash,_add,_new_sig){}
	vector<BYTE>* SM3_LEA();
};

class SHA256LEA : public LEA{
public:
	SHA256LEA(vector<BYTE> _orig = vector<BYTE>(), int _keylen = 32, 
		BYTE * _orig_hash = nullptr, vector<BYTE> _add =vector<BYTE>(),
		BYTE ** _new_sig = nullptr):LEA(_orig,_keylen,_orig_hash,_add,_new_sig){}
	vector<BYTE>* SHA256_LEA();
};
