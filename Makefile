all : arp_spoofing

arp_spoofing: arp_spoofing.cpp
	g++ -g -o arp_spoofing arp_spoofing.cpp -lpcap
clean:
	rm -f arp_spoofing
	rm -f *.o
