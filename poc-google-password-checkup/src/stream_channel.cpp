
#include "stream_channel.h"

const static size_t NETWORK_BUFFER_SIZE = 1024*1024;

NetIO::NetIO(std::string party, std::string address, int port)
{
	this->port = port & 0xFFFF; 

	if(party == "server")
	{
		// create server master socket: socket descriptor is an integer (like a file-handle)
		this->server_master_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
		// set sockaddr_in with IP and port
		struct sockaddr_in server_address; 
		memset(&server_address, 0, sizeof(server_address)); // fill each byte with 0
		socklen_t server_address_size = sizeof(server_address);

		server_address.sin_family = AF_INET; // use IPV4
		if(address==""){
			server_address.sin_addr.s_addr = htonl(INADDR_ANY); // set our address to any interface
		}
		else{
			server_address.sin_addr.s_addr = inet_addr(address.c_str());
		} 
		server_address.sin_port = htons(port);           // set the server port number  

		// set the server master socket
		int reuse = 1;
		if (setsockopt(this->server_master_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
			perror("error: setsockopt");
			exit(EXIT_FAILURE);
		}
	
		// bind the server master socket with IP and port
		if(bind(this->server_master_socket, (struct sockaddr *)&server_address, sizeof(struct sockaddr)) < 0) {
			perror("error: fail to bind server master socket");
			exit(EXIT_FAILURE);
		}

		// begin to listen
		if(listen(this->server_master_socket, 1) < 0) {
			perror("error: server master socket fail to listen");
			exit(EXIT_FAILURE);
		}
		else{
			std::cout << "server is listening connection request from client >>>" << std::endl;
		}	
		// accept request from the client
		struct sockaddr_in client_address; // structure that holds ip and port
		socklen_t client_address_size = sizeof(client_address); 
		// successful return of non-negative descriptor, error return-1
	
		connect_socket = accept(server_master_socket, (struct sockaddr*)&client_address, &client_address_size);


		if (connect_socket < 0) {
			perror("error: fail to accept client socket");
			exit(EXIT_FAILURE);	
		}
	}

	else{
		IS_SERVER = false;  

		// set the server address that the client socket is going to connect
		struct sockaddr_in server_address;
		memset(&server_address, 0, sizeof(server_address));
		server_address.sin_family = AF_INET; 
		server_address.sin_addr.s_addr = inet_addr(address.c_str());
		server_address.sin_port = htons(port);

		// create client socket
		this->connect_socket = socket(AF_INET, SOCK_STREAM, 0);


		if (connect(this->connect_socket, (struct sockaddr *)&server_address, sizeof(struct sockaddr_in)) < 0){
			perror("error: connect");
			exit(EXIT_FAILURE);	
		}
		else{
			std::cout << "client connects to server successfully >>>" << std::endl;
		}
	}
	
	SetNodelay(); 
	// very impprotant: bind the socket to a file stream
	stream = fdopen(this->connect_socket, "wb+"); 
	buffer = new char[NETWORK_BUFFER_SIZE];
	memset(buffer, 0, NETWORK_BUFFER_SIZE);
	setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE); // Specifies a buffer for stream
}


void NetIO::SetNodelay() 
{
	const int one=1;
	setsockopt(this->connect_socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

void NetIO::SetDelay() 
{
	const int zero = 0;
	setsockopt(this->connect_socket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
}

/*
** first define basic send/receive functions
** if we directly use the send/receive socket function
** the buffer will be overflowed when the data is massive
** it is important to buffer the data to the stream, which is binded with the socket
** the underlying mechanism will thus do the slice automatically to ensure the server/client will not crash
** then implement functions send/receiver bytes and more advanced types of data 
*/

// the very basic send function 
void NetIO::SendDataInternal(const void *data, size_t LEN)
{
	size_t HAVE_SENT_LEN = 0; 
	// continue write data to stream until all reach the desired LEN
	while(HAVE_SENT_LEN < LEN) {
		size_t SENT_LEN = fwrite((char*)data+HAVE_SENT_LEN, 1, LEN-HAVE_SENT_LEN, stream);
		if (SENT_LEN >= 0) HAVE_SENT_LEN+=SENT_LEN;
		else fprintf(stderr,"error: fail to send data %zu\n", SENT_LEN);
	}
	/* 
	** very important: 
	** if stream is not explicitly flushed, the data will not be sent
	*/
	fflush(stream); 
}

// the very basic receive function
void NetIO::ReceiveDataInternal(const void *data, size_t LEN)
{
	size_t HAVE_RECEIVE_LEN = 0;
	// continue receive data to stream until all reach the desired LEN
	while(HAVE_RECEIVE_LEN < LEN) {
		size_t RECEIVE_LEN = fread((char*)data+HAVE_RECEIVE_LEN, 1, LEN-HAVE_RECEIVE_LEN, stream);
		if (RECEIVE_LEN >= 0) HAVE_RECEIVE_LEN+=RECEIVE_LEN;
		else fprintf(stderr,"error: fail to receive data %zu\n", RECEIVE_LEN);
	}
}


void NetIO::SendBytes(const void* data, size_t LEN) 
{
	SendDataInternal(data, LEN); 
}

void NetIO::ReceiveBytes(void* data, size_t LEN) 
{
	ReceiveDataInternal(data, LEN); 
}


void NetIO::SendBits(uint8_t *data, size_t LEN) 
{
	SendBytes(data, LEN);
}

void NetIO::ReceiveBits(uint8_t *data, size_t LEN) 
{
	ReceiveBytes(data, LEN);
}

void NetIO::SendString(char *data, size_t LEN) 
{
	SendBytes(data, LEN);
}

void NetIO::ReceiveString(char *data, size_t LEN) 
{
	ReceiveBytes(data, LEN);  
}

void NetIO::SendString(std::string &str) 
{
	SendBytes(&str[0], str.size());
}

void NetIO::ReceiveString(std::string &str) 
{
	ReceiveBytes(&str[0], str.size()); 
}








