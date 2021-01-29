all:
	gcc -Wl,-z,now -fpie -fstack-protector-all wrapper.c -o wrapper
	strip wrapper

clean:
	rm wrapper
