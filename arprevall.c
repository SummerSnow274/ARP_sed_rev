#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#define ARP_REQUEST 1
typedef struct aprhdr{
	u_int16_t htype;	//Hardware type
	u_int16_t ptype;	//protocol type
	u_char hlen;		//Hardware address length
	u_char plen;		//protocol address length
	u_int16_t oper;		//operation code
	u_char sha[6];		//sender hardware address
	u_char spa[4];		//sender ip address
	u_char tha[6];		//target hardware address
	u_char tpa[4];		//target ip address
}arphdr_t;
 
#define MAX 2048
 
int main(int argc, char const *argv[])
{
	int i = 0;
	bpf_u_int32 net = 0, mast = 0;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *des = NULL;
	struct pcap_pkthdr hk;
	const unsigned char *packet = NULL;
	arphdr_t *arp;
	arp = NULL;		//
 
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	des = pcap_open_live(argv[1], MAX, 0, 512, errbuf);		//参数argv[1]不能写成"argv[1]"
	pcap_lookupnet(argv[1], &net, &mast, errbuf);
    pcap_compile(des, &filter, "arp", 1, 0);		//这里出现段错误
	pcap_setfilter(des, &filter);
 	int j;
	j = 0;
	while(1){

		if (j > 300) return 0;
		j++;
		packet  = pcap_next(des, &hk);
		if (packet == NULL)
		{
			continue;
		}
		else{
				arp = (struct arphdr*)(packet + 14);
				if(arp != NULL){
					//printf("\nRecived packet size:\t%d", hk.len);
					//printf("-Hardware type:\t%s", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
					//printf("-Protocol type:\t%s", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown");
					//printf("-Operation:\t%s", (ntohs(arp->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");
		 			if (ntohs(arp->oper) == ARP_REQUEST)
		 				continue;
		 			else
		 			{
		 				if(ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800){	
							printf("\nSender IP: ");
							for(i = 0; i < 4; i++) {
								printf("%d", arp->spa[i]); 
								if (i < 3) {
									printf(".");
								}
							}
							printf("\tSender MAC: ");
							for(i = 0; i < 6; i++) {
								printf("%02X", arp->sha[i]); 
								if (i < 5) {
									printf(":");
								}
							}
						}
		 			}
				}
			
		}

	}
	return 0;
}
