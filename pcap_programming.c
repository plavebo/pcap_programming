#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void packet_handler(unsigned char *data, const struct pcap_pkthdr *packetHeader, const unsigned char *packet) {

    struct ether_header *etherHeader = (struct ether_header *)packet;
    struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    int offset = sizeof(struct ether_header) + sizeof(struct ip) + tcpHeader->th_off * 4;
    int length = packetHeader->len - offset;
    
    printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)etherHeader->ether_shost));
    printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)etherHeader->ether_dhost));

    printf("Src IP: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("Dest IP: %s\n", inet_ntoa(ipHeader->ip_dst));

    printf("Src Port: %d\n", ntohs(tcpHeader->th_sport));
    printf("Det Port: %d\n", ntohs(tcpHeader->th_dport));
    
    if (length > 0) {
        printf("Message: ");
        for (int i = 0; i < length && i < 30; i++) {
            printf("%02X ", packet[offset + i]);
        }
        printf("\n");
    }
}

int main() {
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handler;

    pcap_if_t *alldevs, *dev_list;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Not found network device list: %s\n", errbuf);
        return 1;
    }

    dev = alldevs->name;

    handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handler == NULL) {
        printf("Can't open network device: %s\n", errbuf);
        return 1;
    }
    
    pcap_loop(handler, 0, packet_handler, NULL);

    pcap_close(handler);
    return 0;
}
