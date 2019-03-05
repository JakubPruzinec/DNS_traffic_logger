/* source: https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c */
/* source: https://gist.github.com/njh/84125c8ededdeb74ec5cc80a4003f308 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include <iostream>

namespace utils
{

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/'};

static std::size_t mod_table[] = {0, 2, 1};


/**
 * Encodes data to base64 form
 * @param data Data to be encoded
 * @param dataLength The length of the data
 * @return Data as base64 string
 */
inline std::string encode(const uint8_t *data, size_t dataLength)
{
	std::size_t outputLength = 4 * ((dataLength + 2) / 3);
	std::string encodedData;

	encodedData.reserve(outputLength);

	for (std::size_t i = 0; i < dataLength; )
	{
		uint32_t octet_a = i < dataLength ? (unsigned char)data[i++] : 0;
		uint32_t octet_b = i < dataLength ? (unsigned char)data[i++] : 0;
		uint32_t octet_c = i < dataLength ? (unsigned char)data[i++] : 0;

		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encodedData.push_back(encoding_table[(triple >> 3 * 6) & 0x3F]);
		encodedData.push_back(encoding_table[(triple >> 2 * 6) & 0x3F]);
		encodedData.push_back(encoding_table[(triple >> 1 * 6) & 0x3F]);
		encodedData.push_back(encoding_table[(triple >> 0 * 6) & 0x3F]);
	}

	for (std::size_t i = 0; i < mod_table[dataLength % 3]; i++)
	{
		encodedData[outputLength - 1 - i] = '=';
	}

	return encodedData;
}

inline std::string byteToHex(uint8_t byte)
{
	std::string str;
	str.push_back(byte >> 4);
	str.push_back(byte & 0x0f);

	for (int i = 0; i < 2; i++) {
		if (str[i] > 9)
		{
			str[i] += 39;	
		}

		str[i] += 48;
	}

	return str;
}

} // namespace base64

#endif