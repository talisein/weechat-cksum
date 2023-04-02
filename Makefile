all : cksum.so 

cksumpp.so : cksumpp.o
	g++ -ggdb -std=gnu++1z -shared -fPIC -O3 -o cksumpp.so cksumpp.o

cksumpp.o : cksum.cc
	g++  -ggdb -O3 -D_POSIX_C_SOURCE=200809L -std=gnu++1z -fPIC -Wall -Wextra -fstrict-aliasing -Wstrict-aliasing=2 -O3 -I/usr/local/include/weechat/ -D_GNU_SOURCE -c cksum.cc -o cksumpp.o

cksum.o : cksum.c
	gcc -D_POSIX_C_SOURCE=200809L -std=c11 -fPIC -Wall -Wextra -O3 -fvisibility=hidden -I/usr/local/include/weechat/ -D_GNU_SOURCE -c cksum.c

cksum.so : cksum.o
	gcc -std=c11 -shared -fPIC -O3 -fvisibility=hidden -o cksum.so cksum.o

install : installc

installc : cksum.so
	cp cksum.so ~/.weechat/plugins/cksum.so

installcc : cksumpp.so
	cp cksumpp.so ~/.weechat/plugins/cksumpp.so

clean :
	rm cksum.so cksum.o cksumpp.so cksumpp.o
