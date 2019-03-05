#ifndef _DNS_QUESTION_H_
#define _DNS_QUESTION_H_

#include <iostream>

class DnsQuestion
{
		std::string qname;	/* query name */
		uint16_t qtype;		/* query type */
		uint16_t qclass;	/* query class */

	public:
		DnsQuestion();
		~DnsQuestion();

		const std::string &getQname(void) const;
		uint16_t getQtype(void) const;
		uint16_t getQclass(void) const;

		void setQname(const std::string &qn);
		void setQtype(uint16_t qt);
		void setQclass(uint16_t qc);
};

#endif