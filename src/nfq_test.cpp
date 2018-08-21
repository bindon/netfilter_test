#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>
#include <unordered_map>
#include <main.h>

std::unordered_map<uint32_t, const char *> dnsCacheMap;
FILE *sitesFile;

void printIpAddress(IN const char *prefix, IN uint32_t ipAddress) {
    printf("%s[%d.%d.%d.%d]\n", prefix,
        (ipAddress >> 24) & 0xFF, (ipAddress >> 16) & 0xFF, 
        (ipAddress >>  8) & 0xFF, (ipAddress      ) & 0xFF);
}

bool isFound(IN uint32_t ipAddress) {
    bool ret = false;
    uint32_t minCaret = 0, curCaret, maxCaret;
    char siteName[BUFSIZ];

    // get domain name
    auto iterator = dnsCacheMap.find(ipAddress);
    if(iterator != dnsCacheMap.end()) {
#ifdef VERBOSE
        printf("[*] Finding domain name in filter list...\n");
#endif
        fseek(sitesFile, 0, SEEK_END);
        curCaret = maxCaret = ftell(sitesFile); // file size
        strcpy(siteName, "{"); // '{' is 'z'+1
        
        // seeking file
        while(true) {
            int distance = strcmp(iterator->second, siteName);
            if(!distance) { // hit!
                ret = true;
                printf("[!] Found blacklist URL is [%s]\n", siteName);
                break;
            }
            maxCaret = distance < 0 ? curCaret : maxCaret;
            minCaret = distance > 0 ? curCaret : minCaret;
            if(curCaret == (maxCaret + minCaret) >> 1) { // curCaret == average
                printf("[!] Not Found blacklist URL[%s]\n", iterator->second);
                break;
            }
            curCaret = (maxCaret + minCaret) >> 1; // average(max, min)
            fseek(sitesFile, curCaret, SEEK_SET);
            fgets(siteName, BUFSIZ, sitesFile); // dummy
            fgets(siteName, BUFSIZ, sitesFile); // read Site
            siteName[strcspn(siteName, "\n")] = 0; // remove \n
        }
    }

    return ret;
}

void addDnsPacket(IN unsigned char *udpPacket) {
    DnsStructure *dnsPacket = (DnsStructure *)(udpPacket + sizeof(UdpStructure));
#ifdef VERBOSE 
    printf("[*] 3. DNS Packet Information\n");
    printf("    Transaction ID : 0x%x\n", ntohs(dnsPacket->transactionId));
    printf("    Question Count : %d\n", ntohs(dnsPacket->questionCount));
    printf("    Response Count : %d\n", ntohs(dnsPacket->responseCount));
#endif
    uint8_t *answerPointer = (uint8_t *)((unsigned char *)dnsPacket + sizeof(DnsStructure));

    // get domain name(value)
    char domainName[LENGTH_MAX_DOMAIN_NAME];
    for(int idx=0; idx<ntohs(dnsPacket->questionCount); idx++) {
        char *domainNamePointer = domainName;
        while(*answerPointer) {
            uint8_t length = *answerPointer++;
            memcpy(domainNamePointer, answerPointer, length);
            answerPointer += length;
            domainNamePointer += length;
            *domainNamePointer++ = '.';
        }
        *(domainNamePointer-1) = 0; // NULL
        answerPointer++; // Skip NULL
#ifdef VERBOSE
        printf("[*] 4. Query Domain : %s\n", domainName);
        printf("    Type  : 0x%04x\n", ntohs(*((uint16_t *)(answerPointer  ))));
        printf("    Class : 0x%04x\n", ntohs(*((uint16_t *)(answerPointer+1))));
#endif
        if(ntohl(*((uint32_t *)answerPointer)) != 0x00010001) {
            return; // exception
        }
        answerPointer += 4; // Skip Type + Class
    }

    // get ip address(key)
    for(int idx=0; idx<ntohs(dnsPacket->responseCount); idx++) {
        AnswerStructure *answerPacket = (AnswerStructure *)(answerPointer);
        answerPointer += sizeof(AnswerStructure);
#ifdef VERBOSE
        printf("[*] 5. Answers Packet Information\n");
        printf("    Name  : 0x%04x\n", ntohs(answerPacket->name));
        printf("    Type  : 0x%04x\n", ntohs(answerPacket->type));
        printf("    Class : 0x%04x\n", ntohs(answerPacket->clazz));
        printf("    TTL   : 0x%08x\n", ntohl(answerPacket->timeToLive));
#endif
        if(ntohs(answerPacket->type) == 1 && ntohs(answerPacket->length) == LENGTH_IP_ADDRESS) {
            uint32_t ipAddress = ntohl(*((uint32_t *)answerPointer));
            if(dnsCacheMap.find(ipAddress) == dnsCacheMap.end()) {
                char *dynamicDomainName = new char[strlen(domainName)+1];
                strncpy(dynamicDomainName, domainName, strlen(domainName)); 
                dnsCacheMap.insert(std::make_pair(ipAddress, dynamicDomainName));
                printf("[+] Add DNS Cache [%08x, %s]\n", ipAddress, dynamicDomainName);
            } else {
                printf("[-] Failed to Add DNS Cache(cause: Already Exists)\n");
            }
#ifdef VERBOSE
            printIpAddress("    IP Address  : ", ipAddress);
            printf("    Domain Name : [%s]\n", domainName);
#endif
        }
        answerPointer += ntohs(answerPacket->length);
    }
}

/* returns packet id */
static bool isFiltered(struct nfq_data *tb, u_int32_t &id)
{
    bool result = false;
    int ret;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if(ph) {
        id = ntohl(ph->packet_id);
    }

    if ((ret = nfq_get_payload(tb, &data)) >= 0) {
        IpStructure *ipPacket = (IpStructure *)data;
#ifdef VERBOSE
        printf("\n\n");
        printf("[*] 1. IP Packet Information\n");
        printIpAddress("    Source      IP : ", ntohl(ipPacket->sourceIp));
        printIpAddress("    Destiantion IP : ", ntohl(ipPacket->destinationIp));
        printf("    Protocol       : %04x\n", ipPacket->protocol);
#endif
        if(ipPacket->protocol == IPPROTO_UDP) {
            UdpStructure *udpPacket = (UdpStructure *)((unsigned char *)ipPacket + (ipPacket->headerLength << 2));
#ifdef VERBOSE
            printf("[*] 2. UDP Packet Information\n");
            printf("    Source      Port : %d\n", ntohs(udpPacket->sourcePort));
            printf("    Destination Port : %d\n", ntohs(udpPacket->destinationPort));
            printf("    Length           : %d\n", ntohs(udpPacket->length));
#endif
            if(ntohs(udpPacket->sourcePort) == PORT_DNS) { // iptables or this DNS filter
                addDnsPacket((unsigned char *)udpPacket);
            }
        } else if(ipPacket->protocol == IPPROTO_TCP) {
#ifdef VERBOSE
            printf("[*] 2. TCP Packet\n");
#endif
            result = result || isFound(ntohl(ipPacket->destinationIp))
                            || isFound(ntohl(ipPacket->sourceIp));
        }
    }

    return result;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    bool ret = isFiltered(nfa, id);
    printf("[*][%d] Packet Filter Result : [%s]\n", id, ret ? "DROP" : "ACCEPT");
    return nfq_set_verdict(qh, id, ret ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening sites blacklist file\n");
    if(!(sitesFile = fopen(PATH_SITES_BLACKLIST, "r"))) {
        fprintf(stderr, "error during fopen() - %s\n", PATH_SITES_BLACKLIST);
        exit(1);
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '32768'\n");
    qh = nfq_create_queue(h, 32768, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    if(sitesFile) {
        fclose(sitesFile);
        sitesFile = NULL;
    }
    for(auto iterator=dnsCacheMap.begin(); iterator != dnsCacheMap.end(); iterator++) {
        if(iterator->second) {
            delete iterator->second;
        }
    }
    exit(0);
}

