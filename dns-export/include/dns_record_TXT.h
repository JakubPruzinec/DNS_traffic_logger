#ifndef _DNS_RECORD_TXT_H_
#define _DNS_RECORD_TXT_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordTXT : public DnsAnswer
{
	std::string text;

	public:
		DnsRecordTXT();
		~DnsRecordTXT();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		void setText(const std::string &txt);
};

#endif