#include "dns_question.h"

DnsQuestion::DnsQuestion() : qtype(0), qclass(0)
{
}

DnsQuestion::~DnsQuestion()
{
}

const std::string &DnsQuestion::getQname(void) const
{
	return qname;
}

uint16_t DnsQuestion::getQtype(void) const
{
	return qtype;
}

uint16_t DnsQuestion::getQclass(void) const
{
	return qclass;
}

void DnsQuestion::setQname(const std::string &qn)
{
	qname = qn;
}

void DnsQuestion::setQtype(uint16_t qt)
{
	qtype = qt;
}

void DnsQuestion::setQclass(uint16_t qc)
{
	qclass = qc;
}

