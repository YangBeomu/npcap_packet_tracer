#pragma once

#include <uchar.h>
#include <cstdint>
#include <string>
#include <WS2tcpip.h>

typedef struct TCP_HEADER {
	uint16_t sPort_;
	uint16_t dPort_;
	uint32_t seqNumber;
	uint32_t ackNumber;
	uint16_t headerLen_reserve_flags_;
	uint16_t windowSize_;
	uint16_t checksum;
	uint16_t urgentPointer;

	TCP_HEADER(uint8_t* data) { memcpy_s(this, sizeof(TCP_HEADER), data, sizeof(TCP_HEADER)); };
	uint16_t sPort() { return ntohs(sPort_); };
	uint16_t dPort() { return ntohs(dPort_); };
	uint8_t len() { return ntohs(headerLen_reserve_flags_) & 0b1111000000000000 >> 12; };
	uint8_t flags() { return ntohs(headerLen_reserve_flags_) & 0b0000000000111111; };
}TcpHdr;