#ifndef _DNS_RECORD_CNAME_H_
#define _DNS_RECORD_CNAME_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordCNAME : public DnsAnswer
{
	std::string cName;

	public:
		DnsRecordCNAME();
		~DnsRecordCNAME();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setCname(const std::string &cn);
};

#endif