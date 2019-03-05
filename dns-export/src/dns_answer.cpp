#include "dns_answer.h"

DnsAnswer::DnsAnswer() : rtype(0), rclass(0), rttl(0), rdlength(0)
{

}

DnsAnswer::~DnsAnswer()
{

}

const std::string &DnsAnswer::getRname(void) const
{
	return rname;
}

uint16_t DnsAnswer::getRtype(void) const
{
	return rtype;
}

uint16_t DnsAnswer::getRclass(void) const
{
	return rclass;
}

uint32_t DnsAnswer::getRttl(void) const
{
	return rttl;
}

uint16_t DnsAnswer::getRdlength(void) const
{
	return rdlength;
}


void DnsAnswer::setRname(const std::string &rn)
{
	rname = rn;
}

void DnsAnswer::setRtype(uint16_t rt)
{
	rtype = rt;
}

void DnsAnswer::setRclass(uint16_t rc)
{
	rclass = rc;
}

void DnsAnswer::setRttl(uint32_t ttl)
{
	rttl = ttl;
}

void DnsAnswer::setRdlength(uint16_t rl)
{
	rdlength = rl;
}