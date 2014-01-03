all : cksum.so

cksum.o : cksum.c
	gcc -D_POSIX_C_SOURCE=200809L -std=c11 -fPIC -Wall -Wextra -O3 -fvisibility=hidden -I/usr/local/include/weechat/ -D_GNU_SOURCE -c cksum.c

cksum.so : cksum.o
	gcc -std=c11 -shared -fPIC -O3 -fvisibility=hidden -o cksum.so cksum.o

install : cksum.so
	cp cksum.so ~/.weechat/plugins/cksum.so
