CXX?=g++
CXXFLAGS+=-c -Wall -std=c++11


all: SM3test

SM3test: SM3test.o SM3.o
	$(CXX) SM3test.o SM3.o -lcrypto -o SM3test

SM3test.o:
	$(CXX) $(CXXFLAGS) SM3test.cpp 
SM3.o:
	$(CXX) $(CXXFLAGS) SM3.cpp 

clean:
	rm *.o SM3test