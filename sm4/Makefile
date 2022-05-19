BIN		    = sm4_test_speed
OBJS		= sm4_test_speed.o sm4_basic.o sm4_T.o sm4_avx2.o sm4_setkey.o
# BIN        = sm4_test_correctness
# OBJS		=  sm4_test_correctness.o sm4_basic.o sm4_T.o sm4_avx2.o sm4_setkey.o
DIST		= main

CC		= g++
CFLAGS		= -Wall -std=c++11 -Ofast -march=native -DSM4NI_UNROLL -mavx2 -msse2 -msse -maes -lcrypto
$(BIN): $(OBJS)
	$(CC) $(LDFLAGS)  -o $(BIN) $(OBJS) $(LIBS) -lbenchmark 
.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)
