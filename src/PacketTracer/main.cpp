#include "pch.h"

#include "PacketTracer.h"

using namespace std;

vector<char*> arguments;

void usage() {
	cout << "PackteTrace need arguments" << endl;
	cout << "./PacketTracer.exe [interface][source ip]" << endl;
}

bool parse(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}

	return true;
}

int main(int argc, char* argv[], char* env) {
	if (!parse(argc, argv)) return -1;

	string interfaceName = argv[1];
	string sourceIP = argv[2];

	PacketTracer pt(interfaceName.c_str());

	while (1) {
		pt.ReadPacket({}, IpHdr::PROTOCOL_ID_TYPE::TCP);

		//Sleep(100);

		if (_kbhit())
			if (_getch() == 27) break;
	}
}