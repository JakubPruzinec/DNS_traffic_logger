#ifndef _DNS_ANSWER_H_
#define _DNS_ANSWER_H_

#include <iostream>
#include <vector>

class DnsAnswer
{
		std::string rname;			/* response name */
		uint16_t rtype;				/* response type */
		uint16_t rclass;			/* response class */
		uint32_t rttl;				/* the number of seconds the answer can be cached */
		uint16_t rdlength;			/* declared data length */

	public:
		DnsAnswer();
		~DnsAnswer();

		const std::string &getRname(void) const;
		uint16_t getRtype(void) const;
		uint16_t getRclass(void) const;
		uint32_t getRttl(void) const;
		uint16_t getRdlength(void) const;
		virtual std::string getData(void) const = 0;
		virtual std::string getType(void) const = 0;

		void setRname(const std::string &rn);
		void setRtype(uint16_t rt);
		void setRclass(uint16_t rc);
		void setRttl(uint32_t ttl);
		void setRdlength(uint16_t rl);
};

#endif