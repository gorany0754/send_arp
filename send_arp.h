#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

void print_mac(unsigned char* mac);
unsigned char* set_eth_arp(struct ether_header *eth,struct ether_arp *arp, unsigned char* dst_mac, unsigned char* src_mac, unsigned char *dst_ip, unsigned char* src_ip, int opcode);
unsigned char* send_packet(unsigned char* data,unsigned char* mac,const char* ip,unsigned char* interface, struct pcap_pkthdr *header,int opcode);
