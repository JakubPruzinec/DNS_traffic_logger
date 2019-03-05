#ifndef _DNS_RECORD_NS_H_
#define _DNS_RECORD_NS_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordNS : public DnsAnswer
{
	std::string nameServer;

	public:
		DnsRecordNS();
		~DnsRecordNS();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setNameServer(const std::string &ns);
};

#endif