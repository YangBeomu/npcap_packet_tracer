#pragma once

#include <uchar.h>
#include <cstdint>

typedef uint16_t u_int16_t;
typedef uint32_t Ip;

#pragma pack(push, 1)
typedef struct IP_HEADER final {
    enum PROTOCOL_ID_TYPE {
        HOPOST = 0,
        ICMP,
        IGMP,
        GGP,
        IPv4,
        ST,
        TCP,
    };

    u_char version_headerLen_;
    u_char TOS_;
    u_int16_t totalPacketLen_;
    u_int16_t id;

    u_int16_t flags_fragOffset_;

    u_char ttl_;
    u_char protocolId_;
    u_int16_t headerChecksum_;

    Ip sIp_;
    Ip dIp_;

    IP_HEADER(u_char* data) { memcpy_s(this, sizeof(IP_HEADER), data, sizeof(IP_HEADER)); }

    u_char version() { return (version_headerLen_ & 0b11110000) >> 4; }
    u_char len() { return (version_headerLen_ & 0b00001111) * 4; }
    u_char flags() { return (ntohs(flags_fragOffset_) & 0b1110000000000000) >> 13; };
    u_int16_t fragOffset() { return ntohs(flags_fragOffset_) & 0b0001111111111111; };
}IpHdr;
#pragma pack(pop)

typedef IpHdr* PIpHdr;
