#include "dns_packet.h"

DnsPacket::DnsPacket()
{
}

DnsPacket::~DnsPacket()
{
}



/**
 * Gets dns Header
 * @return Header reference
 */
const struct dnshdr &DnsPacket::getHeader(void) const
{
	return header;
}

/**
 * Gets dns Questions
 * @return Questions reference
 */
const std::vector<std::unique_ptr<DnsQuestion>> &DnsPacket::getQuestions(void) const
{
	return questions;
}

/**
 * Gets dns Answers
 * @return Answers reference
 */
const std::vector<std::unique_ptr<DnsAnswer>> &DnsPacket::getAnswers(void) const
{
	return answers;
}

/**
 * Sets dns Header
 * @param hdr Dns Header
 */
void DnsPacket::setHeader(const struct dnshdr &hdr)
{
	header = hdr;
}

/**
 * Adds dns Question
 * @param question Dns Question
 */
void DnsPacket::addQuestion(std::unique_ptr<DnsQuestion>&& question)
{
	questions.push_back(std::move(question));
}

/**
 * Adds dns Answer
 * @param answer Dns Answer
 */
void DnsPacket::addAnswer(std::unique_ptr<DnsAnswer>&& answer)
{
	answers.push_back(std::move(answer));
}

/**
 * Dumps a dns packet
 */
void DnsPacket::dump(void) const
{
	for (std::size_t i = 0; i < questions.size(); i++)
	{
		auto q = &*questions[i];
		std::cerr << std::to_string(i) << ". [Q] " << q->getQname() << " "
					<< std::to_string(q->getQtype()) << " " << std::to_string(q->getQclass()) << std::endl;
	}

	for (std::size_t i = 0; i < answers.size(); i++)
	{
		auto a = &*answers[i];
		std::cerr << std::to_string(i) << ". [A] " << a->getRname() << " "
					<< a->getType() << " [" << a->getData() << "]" << std::endl;
	}
}