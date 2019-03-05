#include "dns_record_TXT.h"

DnsRecordTXT::DnsRecordTXT()
{
}

DnsRecordTXT::~DnsRecordTXT()
{
}

std::string DnsRecordTXT::getData(void) const
{
	return text;
}

std::string DnsRecordTXT::getType(void) const
{
	std::string prefix = "v=spf1";
	if (!text.compare(0, prefix.size(), prefix))
	{
		return "SPF";
	}

	return "TXT";
}

void DnsRecordTXT::setText(const std::string &txt)
{
	text = txt;
}