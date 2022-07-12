/*
** Modified from the following project
** 1. https://github.com/emp-ot/
*/

#ifndef KUNLUN_NET_IO_STREAM_CHANNEL
#define KUNLUN_NET_IO_STREAM_CHANNEL


#include "head.h"

class NetIO{ 
public:
	bool IS_SERVER;
	int server_master_socket = -1; 
	int connect_socket = -1;
	FILE *stream = nullptr; 
	char *buffer = nullptr; 

	std::string address;
	int port;

	NetIO(std::string party, std::string address, int port); 
	NetIO() = default;
	void SetNodelay();
	void SetDelay();

	void SendDataInternal(const void *data, size_t LEN); 
	void ReceiveDataInternal(const void *data, size_t LEN); 

	void SendBytes(const void *data, size_t LEN);  
	void ReceiveBytes(void *data, size_t LEN); 


	void SendBits(uint8_t *data, size_t LEN);
	void ReceiveBits(uint8_t *data, size_t LEN); 

	void SendString(char *data, size_t LEN);
	void ReceiveString(char *data, size_t LEN); 

	void SendString(std::string &str);
	void ReceiveString(std::string &str); 

	template <typename T>
	void SendInteger(const T &n);

	template <typename T>
	void ReceiveInteger(T &n);

	~NetIO() {
		close(this->connect_socket); 
		if(IS_SERVER == true){
			close(this->server_master_socket); 
		}
		fflush(stream);
		fclose(stream);
		delete[] buffer;
	}
};
// T could be any built-in data type, such as block or int
template <typename T>
void NetIO::SendInteger(const T &n)
{
	SendBytes(&n, sizeof(T));
}
template <typename T>
void NetIO::ReceiveInteger(T &n)
{
	ReceiveBytes(&n, sizeof(T));
}

#endif
