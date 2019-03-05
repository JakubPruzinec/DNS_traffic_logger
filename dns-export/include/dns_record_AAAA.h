#ifndef _DNS_RECORD_AAAA_H_
#define _DNS_RECORD_AAAA_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordAAAA : public DnsAnswer
{
	std::string address;

	public:
		DnsRecordAAAA();
		~DnsRecordAAAA();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setAddress(const std::string &addr);
};

#endif