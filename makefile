LDLIBS=-lpcap

all: arp-spoofing

main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

getIpMac.o : getIpMac.h getIpMac.cpp

arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o getIpMac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoofing *.o
