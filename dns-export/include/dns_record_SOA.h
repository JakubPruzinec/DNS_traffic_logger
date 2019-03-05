#ifndef _DNS_RECORD_SOA_H_
#define _DNS_RECORD_SOA_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordSOA : public DnsAnswer
{
	std::string mName;
	std::string rName;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;

	public:
		DnsRecordSOA();
		~DnsRecordSOA();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setMname(const std::string &mn);
		void setRname(const std::string &rn);
		void setSerial(uint32_t s);
		void setRefresh(uint32_t ref);
		void setRetry(uint32_t ret);
		void setExpire(uint32_t exp);
};

#endif