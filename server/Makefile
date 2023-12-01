# make
# make clean
# export PATH=$PATH:/home/jan/learning/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu/bin && make CROSS_COMPILE=aarch64-none-linux-gnu-

CC=$(CROSS_COMPILE)gcc
CFLAGS += -Wall -Werror

all: aesdsocket.c
	$(CC) -o aesdsocket aesdsocket.c -I. $(CFLAGS)

clean:
	rm -f *.o aesdsocket