
typedef unsigned char BYTE;
void DigestToRaw(string hash, unsigned char * raw)
{
	transform(hash.begin(), hash.end(), hash.begin(), ::tolower);
	string alpha("0123456789abcdef");
	for(unsigned int x = 0; x < (hash.length() / 2); x++)
	{
		raw[x] = (unsigned char)((alpha.find(hash.at((x * 2))) << 4));
		raw[x] |= (unsigned char)(alpha.find(hash.at((x * 2) + 1)));
	}
}

vector<BYTE> String2Vector(BYTE* str)
{
	vector<BYTE> s;
	for(unsigned int x = 0; x < strlen((char*)str); x++)
	{
		s.push_back(str[x]);
	}
	return s;
}

vector<BYTE> GenerateRandomString()
{
	string alpha("0123456789abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ");
	srand (time(NULL));
	vector<BYTE> * s = new vector<BYTE>();
	int length = rand() % 128;
	for(unsigned int  x = 0; x < length; x++)
	{
		s->push_back(alpha[rand() % 62]);
	}
	return *s;
}

void print_BYTE2string(vector<BYTE> *s,int size = 0){
	if(size == 0) size =  s -> size();
	for(unsigned int x = 0; x < s->size(); x++)
	{
		unsigned char c = s->at(x);
		if(c >= 32 && c <= 126)
		{
			cout << c;
		}
		else
		{
			printf("\\x%02x", c);
		}
	}
	printf("\n");
}

void print_BYTE2string(BYTE* str,int size = 0){
	vector<BYTE> s = String2Vector(str);
	if(size == 0) size =  s.size();
	 print_BYTE2string(&s,size);
}

void printf_BYTE(vector<BYTE> *s,int size = 0){
	if(size == 0) size =  s -> size();
	for(unsigned int x = 0; x < size; x++)
	{
		printf("%02x", (*s)[x]);
	}
	printf("\n");
}
void printf_BYTE(BYTE* str,int size = 0){
	vector<BYTE> s = String2Vector(str);
	if(size == 0) size =  s.size();
	printf_BYTE(&s,size);
}