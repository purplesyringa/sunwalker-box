obj-m += sunwalker.o
PWD := $(CURDIR)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	strip --strip-debug sunwalker.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
