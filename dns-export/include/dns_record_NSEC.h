#ifndef _DNS_RECORD_NSEC_H_
#define _DNS_RECORD_NSEC_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordNSEC : public DnsAnswer
{
	std::string nextDomainName;
	std::string typesBitmap;

	public:
		DnsRecordNSEC();
		~DnsRecordNSEC();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		const std::string &getNextDomainName(void) const;
		const std::string &getTypesBitmap(void) const;

		void setNextDomainName(const std::string &name);
		void setTypesBitmap(const std::string &types);
};

#endif