#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void usage() {
    printf("syntax: pcap-test\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

void print_mac(uint8_t* m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_payload(const u_char* payload, int length) {
    int i;
    for (i = 0; i < length && i < 10; i++)
        printf("%02x ", payload[i]);
    printf("\n");
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
	printf("------------------------------\n");
        printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        printf("smac: ");
        print_mac(eth_hdr->ether_shost);
        printf("\n");
        printf("dmac: ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue;

        struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct libnet_ethernet_hdr));
        printf("s-ip: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("d-ip: %s\n", inet_ntoa(ip_hdr->ip_dst));

        if (ip_hdr->ip_p == 0x06) { // 0x06 is the hexadecimal value for IPPROTO_TCP
            struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_hdr->ip_hl * 4);
            printf("s-port: %u\n", ntohs(tcp_hdr->th_sport));
            printf("d-port: %u\n", ntohs(tcp_hdr->th_dport));

            int tcp_header_length = tcp_hdr->th_off * 4;
            int payload_length = header->caplen - sizeof(struct libnet_ethernet_hdr) - ip_hdr->ip_hl * 4 - tcp_header_length;
            if (payload_length > 0) {
                printf("Data (hex value, up to 10 bytes): ");
                print_payload((const u_char*)tcp_hdr + tcp_header_length, payload_length);
            }
	    printf("------------------------------");
        }
    }

    pcap_close(pcap);
    return 0;
}

