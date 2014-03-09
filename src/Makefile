CC=g++
CFLAGS=-O3 -fPIC
LDFLAGS=-lboost_random -shared

include /etc/os-release
NULL		:=
SPACE		:= ${NULL} ${NULL}
${SPACE}	:= ${SPACE}
TARGET		:= $(subst ",,$(subst ${ },_,${ID}))

default: ${TARGET}

debian: CFLAGS += -I/usr/include/python3.2
debian: LDFLAGS += -lboost_python-py32 -lpython3.2mu
debian: all

fedora: CFLAGS += -I/usr/include/python3.3m
fedora: LDFLAGS += -lboost_python3 -lpython3
fedora: all

arch: CFLAGS += -I/usr/include/python3.3m
arch: LDFLAGS += -lboost_python3 -lpython3
arch: all

raspbian: debian

all: pySilkroadSecurity

pySilkroadSecurity: main.o blowfish.o silkroad_security.o stream_utility.o
	$(CC) $(LDFLAGS) main.o blowfish.o silkroad_security.o stream_utility.o -o pySilkroadSecurity.so

main.o: main.cpp
	$(CC) $(CFLAGS) -c main.cpp

silkroad_security.o: SilkroadSecurity/silkroad_security.cpp
	$(CC) $(CFLAGS) -c SilkroadSecurity/silkroad_security.cpp

blowfish.o: SilkroadSecurity/blowfish.cpp
	$(CC) $(CFLAGS) -c SilkroadSecurity/blowfish.cpp

stream_utility.o: SilkroadSecurity/stream_utility.cpp
	$(CC) $(CFLAGS) -c SilkroadSecurity/stream_utility.cpp

clean:
	rm -f *.o

install:
	cp pySilkroadSecurity.so ../python/
