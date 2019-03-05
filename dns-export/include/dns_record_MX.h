#ifndef _DNS_RECORD_MX_H_
#define _DNS_RECORD_NS_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordMX : public DnsAnswer
{
	uint16_t preference;
	std::string mailServer;

	public:
		DnsRecordMX();
		~DnsRecordMX();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setPreference(uint16_t p);
		void setMailServer(const std::string &ms);
};

#endif