CFLAGS = -std=c++11 -Wall -Wextra -g -I ./include
CCX = g++


HDRDEP = $(wildcard *.h)


all:
	make dns-export

clear:
	rm build/*.o dns-export


# COMPILE OBJECTS
main.o: $(HDRDEP) src/main.cpp
	$(CCX) $(CFLAGS) src/main.cpp -c -o build/main.o

global.o: $(HDRDEP) src/global.cpp
	$(CCX) $(CFLAGS) src/global.cpp -c -o build/global.o

dns_capture.o: $(HDRDEP) src/dns_capture.cpp
	$(CCX) $(CFLAGS) src/dns_capture.cpp -c -o build/dns_capture.o

dns_packet.o: $(HDRDEP) src/dns_packet.cpp
	$(CCX) $(CFLAGS) src/dns_packet.cpp -c -o build/dns_packet.o

dns_question.o: $(HDRDEP) src/dns_question.cpp
	$(CCX) $(CFLAGS) src/dns_question.cpp -c -o build/dns_question.o

dns_record_A.o: $(HDRDEP) src/dns_record_A.cpp
	$(CCX) $(CFLAGS) src/dns_record_A.cpp -c -o build/dns_record_A.o

dns_record_AAAA.o: $(HDRDEP) src/dns_record_AAAA.cpp
	$(CCX) $(CFLAGS) src/dns_record_AAAA.cpp -c -o build/dns_record_AAAA.o

dns_record_CNAME.o: $(HDRDEP) src/dns_record_CNAME.cpp
	$(CCX) $(CFLAGS) src/dns_record_CNAME.cpp -c -o build/dns_record_CNAME.o

dns_record_NS.o: $(HDRDEP) src/dns_record_NS.cpp
	$(CCX) $(CFLAGS) src/dns_record_NS.cpp -c -o build/dns_record_NS.o

dns_record_SOA.o: $(HDRDEP) src/dns_record_SOA.cpp
	$(CCX) $(CFLAGS) src/dns_record_SOA.cpp -c -o build/dns_record_SOA.o

dns_record_MX.o: $(HDRDEP) src/dns_record_MX.cpp
	$(CCX) $(CFLAGS) src/dns_record_MX.cpp -c -o build/dns_record_MX.o

dns_record_TXT.o: $(HDRDEP) src/dns_record_TXT.cpp
	$(CCX) $(CFLAGS) src/dns_record_TXT.cpp -c -o build/dns_record_TXT.o

dns_record_DNSKEY.o: $(HDRDEP) src/dns_record_DNSKEY.cpp
	$(CCX) $(CFLAGS) src/dns_record_DNSKEY.cpp -c -o build/dns_record_DNSKEY.o

dns_record_RRSIG.o: $(HDRDEP) src/dns_record_RRSIG.cpp
	$(CCX) $(CFLAGS) src/dns_record_RRSIG.cpp -c -o build/dns_record_RRSIG.o

dns_record_NSEC.o: $(HDRDEP) src/dns_record_NSEC.cpp
	$(CCX) $(CFLAGS) src/dns_record_NSEC.cpp -c -o build/dns_record_NSEC.o

dns_record_DS.o: $(HDRDEP) src/dns_record_DS.cpp
	$(CCX) $(CFLAGS) src/dns_record_DS.cpp -c -o build/dns_record_DS.o

dns_answer.o: $(HDRDEP) src/dns_answer.cpp
	$(CCX) $(CFLAGS) src/dns_answer.cpp -c -o build/dns_answer.o

parser.o: $(HDRDEP) src/parser.cpp
	$(CCX) $(CFLAGS) src/parser.cpp -c -o build/parser.o


# LINK OBJECTS
dns-export: main.o global.o dns_capture.o dns_packet.o parser.o dns_question.o dns_answer.o dns_record_A.o dns_record_AAAA.o dns_record_NS.o dns_record_CNAME.o dns_record_SOA.o dns_record_MX.o dns_record_TXT.o dns_record_DNSKEY.o dns_record_RRSIG.o dns_record_NSEC.o dns_record_DS.o
	$(CCX) $(CFLAGS) -pthread -lpcap build/dns_record_RRSIG.o build/dns_record_NSEC.o build/dns_record_DS.o build/dns_record_DNSKEY.o build/dns_record_TXT.o build/dns_record_MX.o build/dns_record_SOA.o build/dns_record_CNAME.o build/dns_record_NS.o build/dns_record_AAAA.o build/dns_record_A.o build/dns_question.o build/dns_answer.o build/parser.o build/dns_packet.o build/dns_capture.o build/global.o build/main.o -o dns-export