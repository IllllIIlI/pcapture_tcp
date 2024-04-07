#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "pcapture.h"

void print_mac_address(const char *label, const u_char *mac_address) {
  printf("%s: ", label);
  for (int i = 0; i < 6; i++) {
    printf("%02X:", mac_address[i]);
  }
  printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol == IPPROTO_TCP) {
      struct tcpheader *tcp =
          (struct tcpheader *)(packet + sizeof(struct ethheader) +
                               (ip->iph_ihl * 4));
      const u_char *message = packet + sizeof(struct ethheader) +
                              (ip->iph_ihl * 4) + TH_OFF(tcp) * 4;

      printf("-------------------------------\n");
      printf("Packet received\n");
      printf("src ip:port : %s:%d\n", inet_ntoa(ip->iph_sourceip), ntohs(tcp->tcp_sport));
      printf("dst ip:port : %s:%d\n", inet_ntoa(ip->iph_destip), ntohs(tcp->tcp_sport));
      print_mac_address("src mac", eth->ether_shost);
      print_mac_address("dst mac", eth->ether_dhost);
      printf("\n");
      int count = 1;
      for (int i = 0; i < 256; i++) {
        printf("%02X ", message[i]);
        if (count % 10 == 0) {
          printf("\n");
        }
        count++;
      }
      printf("\n");
      printf("------------------------------\n");
      printf("\n");
    }
  }
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live(
      "eth0", BUFSIZ, 1, 1000,
      errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);

  return 0;
}
