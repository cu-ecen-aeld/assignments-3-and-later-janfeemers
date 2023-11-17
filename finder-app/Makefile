# [x] A default target which builds the “writer” application
# [x] A clean target which removes the “writer” application and all .o files
# [x] Support for cross-compilation.
#     You should be able to generate an application for the native build platform when GNU make variable CROSS_COMPILE is not specified on the make command line.
#     When CROSS_COMPILE is specified with aarch64-none-linux-gnu- (note the trailing -)your makefile should compile successfully using the cross compiler installed in step 1.

# make
# make clean
# export PATH=$PATH:/home/jan/learning/arm-gnu-toolchain-13.2.Rel1-x86_64-aarch64-none-linux-gnu/bin && make CROSS_COMPILE=aarch64-none-linux-gnu-

CC=$(CROSS_COMPILE)gcc

all: writer.c
	$(CC) -o writer writer.c -I.

clean:
	rm -f *.o writer