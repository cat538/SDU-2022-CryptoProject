CXX?=g++
CXXFLAGS+=-c -Wall -std=c++11


all: LEAtest

LEAtest: LEAtest.o SHA256LEA.o SM3LEA.o
	$(CXX) LEAtest.o SHA256LEA.o  SM3LEA.o SM3.o -lcrypto -o LEAtest

LEAtest.o: 
	$(CXX) $(CXXFLAGS) LEAtest.cpp

SHA256LEA.o: 
	$(CXX) $(CXXFLAGS) SHA256LEA.cpp

SM3LEA.o: 
	$(CXX) $(CXXFLAGS) SM3LEA.cpp

SM3.o:
clean:
	rm *.o LEAtest 