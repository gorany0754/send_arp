#include "send_arp.h"

void print_mac(unsigned char* mac){
	for(int i=0;i<5;i++){
		printf("%02x:",mac[i]);
	}
	printf("%02x\n",mac[5]);
}

unsigned char* set_eth_arp(struct ether_header *eth,struct ether_arp *arp, unsigned char* dst_mac, unsigned char* src_mac, unsigned char *dst_ip, unsigned char* src_ip, int opcode){
	//write ether_header
	memcpy(eth->ether_dhost,dst_mac,6);
	memcpy(eth->ether_shost,src_mac,6);	
	eth->ether_type=ntohs(ETHERTYPE_ARP);

	//write arp_header
	arp->arp_hrd=htons(ARPHRD_ETHER);
	arp->arp_pro=htons(ETHERTYPE_IP);
	arp->arp_hln=ETHER_ADDR_LEN;
	arp->arp_pln=sizeof(in_addr_t);
	if(opcode==1){
		arp->arp_op=htons(ARPOP_REQUEST);
	}
	else arp->arp_op=htons(ARPOP_REPLY);
	if(dst_mac!=NULL){
		memcpy(arp->arp_tha,dst_mac,6);
	}
	else memset(arp->arp_tha,'\x00',6);
	memcpy(arp->arp_sha,src_mac,6);
	inet_aton(dst_ip,arp->arp_tpa);
	inet_aton(src_ip,arp->arp_spa);

	//stick eth and arp
	unsigned char *packet=(unsigned char*)malloc(sizeof(struct ether_header)+sizeof(struct ether_arp));
	memset(packet,0x00,sizeof(struct ether_header)+sizeof(struct ether_arp));
	memcpy(packet,eth,sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header),arp,sizeof(struct ether_arp));
	return packet;
}

unsigned char* send_packet(unsigned char* data,unsigned char* mac,const char* ip,unsigned char* interface, struct pcap_pkthdr *header,int opcode){

	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char* packet;
	pcap_t *handle;
	int res; //return value of pcap_next_ex()

	handle=pcap_open_live(interface,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		fprintf(stderr,"couldn't open device %s:%s\n",interface,errbuf);
		exit(1);
	}

	//arp request
	if(opcode==1){
		if(pcap_sendpacket(handle,data,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
			printf("invalid packet");
			pcap_close(handle);
			exit(1);
		}
		while(1){
			res=pcap_next_ex(handle,&header,&packet);
			struct ether_header *etherneth;
			etherneth=(struct ether_header*)packet;
			if(ntohs(etherneth->ether_type)==ETHERTYPE_ARP){
				memcpy(mac, data[6], 6*sizeof(unsigned char));
				return mac;
			}
			if(res==0)continue;
			if(res<0)break;
		}
		pcap_close(handle);
	}
	//arp reply
	else if(opcode==2){
		while(1){
			if(pcap_sendpacket(handle,data,sizeof(struct ether_header)+sizeof(struct ether_arp))==-1){
				printf("invalid packet");
				pcap_close(handle);
				exit(1);
			}
		}
		return NULL;
	}
}
