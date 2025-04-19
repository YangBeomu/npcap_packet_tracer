#pragma once

#include <string>
#include <vector>

#include "pcap.h"
#include "ethhdr.h"
#include "iphdr.hpp"
#include "tcphdr.hpp"

class PacketTracer
{
	pcap* pcap_ = nullptr;

	void ShowPacket();

public:
	PacketTracer(std::string interfaceTitle);
	~PacketTracer();

	void ReadPacket(const std::string ip = {}, int protocolType = -1);
};

