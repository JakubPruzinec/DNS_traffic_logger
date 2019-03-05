#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include <iostream>
#include <unistd.h>
#include <pcap.h>
#include <memory>

#include "dns_capture.h"

class DnsCapture;

namespace global
{
	extern bool quit;
	extern bool userInt;
	extern std::string pcapFile;
	extern std::string interface;
	extern std::string syslogServer;
	extern uint32_t timeOut;
	extern std::string hostName;
	extern pid_t pid;
	extern pcap_t *handle;
	extern std::unique_ptr<DnsCapture> dnsCapture;

	bool processCmdLine(int argc, char **argv);

	bool initStructures(void);

	void manual(void);

	void setSignals(void);
	bool maskMainSignals(void);

	void sender(void);
} // global

#endif