#ifndef _MAIN_H
#define _MAIN_H
#include <stdint.h>
#define IN
#define OUT

#define LENGTH_IP_ADDRESS 4
#define LENGTH_MAX_DOMAIN_NAME 256
#define PORT_DNS 53
#define PATH_SITES_BLACKLIST "../res/BlackSites.lst"

#pragma pack(push, 1)
typedef struct _IpStructure {
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t  headerLength:4, 
             version:4;
#elif BYTE_ORDER == BIG_ENDIAN
    uint8_t  version:4,
             headerLength:4; 
#endif
    uint8_t  typeOfService;
    uint16_t totalLength;
    uint16_t id;
    uint16_t offset;
    uint8_t  timeToLive;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t sourceIp;
    uint32_t destinationIp;
} IpStructure;

typedef struct _UdpStructure {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;
} UdpStructure;

typedef struct _DnsStructure {
    uint16_t transactionId;
    uint16_t flags;
    uint16_t questionCount;
    uint16_t responseCount;
    uint16_t authorityCount;
    uint16_t additionalCount;
} DnsStructure;

typedef struct _AnswerStructure {
    uint16_t name;
    uint16_t type;
    uint16_t clazz;
    uint32_t timeToLive;
    uint16_t length;
} AnswerStructure;

#pragma pack(pop)
#endif

