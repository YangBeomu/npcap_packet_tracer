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

	try{
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

void PacketTracer::ReadPacket(const string sip, int protocolType) {
	pcap_pkthdr* header{};
	u_char* packet{};

	if (pcap_next_ex(this->pcap_, &header, (const u_char**)&packet) != 1) return;

	EthHdr* etherHeader = reinterpret_cast<EthHdr*>(packet);
	/*for (int i = 0; i < 6; i++)
		printf("%2x:", etherHeader->smac().address[i]);
	cout << endl;
	for (int i = 0; i < 6; i++)
		printf("%2x:", etherHeader->dmac().address[i]);
	cout << endl;*/

	IpHdr ipHeader(packet + sizeof(EthHdr));

	if (!sip.empty() && ipHeader.sip().compare(sip) != 0) return;

	//cout << "source ip : " << ipHeader.sip() << endl;
	//cout << "destination ip : " << ipHeader.dip() << endl;
	
	if (protocolType == -1 || ipHeader.protocolId_ != protocolType) return;
	
	switch (protocolType) {
		case IpHdr::PROTOCOL_ID_TYPE::ICMP: {
				cout << "icmp detected \n";
			break;
		}
		case IpHdr::PROTOCOL_ID_TYPE::TCP: {
				//cout << "tcp detected \n";
			TcpHdr* tcpHeader = reinterpret_cast<TcpHdr*>(packet + sizeof(EthHdr) + ipHeader.len());
			printf("%d \n", tcpHeader->sPort());
			printf("%d \n", tcpHeader->dPort());
			break;
		}
		default:
			break;
	}
}


