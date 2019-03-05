#ifndef _DNS_RECORD_A_H_
#define _DNS_RECORD_A_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordA : public DnsAnswer
{
	std::string address;

	public:
		DnsRecordA();
		~DnsRecordA();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setAddress(const std::string &addr);
};

#endif