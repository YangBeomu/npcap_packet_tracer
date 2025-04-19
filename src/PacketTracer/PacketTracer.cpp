#include "pch.h"
#include "PacketTracer.h"

using namespace std;

PacketTracer::PacketTracer(string interfaceTitle) {

	char errBuf[PCAP_ERRBUF_SIZE] = { 0, };

	try {
		this->pcap_ = pcap_open_live(interfaceTitle.c_str(), 65535, 1, 1, errBuf);
		if (pcap_ == NULL)
			throw runtime_error("Failed to open");
	}
	catch (const exception& e) {
		cerr << "Failed to create PacketTracer : " << e.what() << endl;
		cerr << "Error : " << errBuf << endl;
		exit(1);
	}
}

PacketTracer::~PacketTracer() {
	pcap_close(this->pcap_);
}

void PacketTracer::ShowPacket() {
	pcap_pkthdr* header{};
	const u_char* packet{};

	try {
		if (pcap_next_ex(this->pcap_, &header, /*(const u_char**)*/&packet) != 1)
			throw runtime_error("Failed to read packet");

		cout << "header cap len : " << header->caplen << endl;
		packet += sizeof(EthHdr);
		IpHdr* ipHeader = (IpHdr*)packet;

		char buf[INET_ADDRSTRLEN]{};

		inet_ntop(AF_INET, &ipHeader->sIp_, buf, sizeof(buf));
		cout << "source ip : " << buf << endl;
		inet_ntop(AF_INET, &ipHeader->dIp_, buf, sizeof(buf));
		cout << "destination ip : " << buf << endl;

	}
	catch (const exception& e) {
		char buf[BUFSIZ]{};
		cerr << "Failed to ReadPacket : " << e.what() << endl;
		cerr << "Error : " << errno << " (" << strerror_s<BUFSIZ>(buf, errno) << endl;
	}
}

void PacketTracer::ReadPacket(const string sip) {
	pcap_pkthdr* header{};
	u_char* packet{};

	if (pcap_next_ex(this->pcap_, &header, (const u_char**)&packet) != 1)
		return;

	packet += sizeof(EthHdr);
	IpHdr ipHeader(packet);

	char buf[INET_ADDRSTRLEN]{};

	inet_ntop(AF_INET, &ipHeader.sIp_, buf, sizeof(buf));

	if (sip.compare(buf) == 0)
		printf("Find packet \n");
	else
		return;
}


