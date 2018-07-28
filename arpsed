//learn from network

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

unsigned char ip[4];        //目标ip
int get_eth_MAC(char *eth_name, unsigned char *MAC);
int get_eth_IP(char *eth_name, unsigned char *IP);
int get_eth_broadaddr(char *eth_name, unsigned char *broadaddr);
int change_InputIpForm(char *ipc);
typedef struct{
    //DLC HEADER
    unsigned char dlc_dst_mac[6];
    unsigned char dlc_src_mac[6];
    unsigned short dlc_frame;

    //ARP PACKET
    unsigned short arp_hwtype;
    unsigned short arp_protype;
    unsigned char   arp_hwlen;
    unsigned char   arp_prolen;
    unsigned short arp_op;
    unsigned char arp_src_mac[6];
    unsigned char arp_src_ip[4];
    unsigned char arp_dst_mac[6];
    unsigned char arp_dst_ip[4];
    unsigned char arp_padding[18];
}arp_packet;

int main(int argc, char const *argv[])
{

    printf("sizeof(arp_packet)=%d\n", sizeof(arp_packet));
    //fill ARP packet

    printf("输入的网卡是:%s\n", argv[1]);
    change_InputIpForm(argv[2]);
    arp_packet arp_pck;
    unsigned char brd_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};  //广播地址
    //unsigned char dst_ip[4];              //数组传递不太会，使用全局变量
    /*
    for (int i = 0; i < 4; ++i){
        printf("%d ", ip[i]);}    //打印检测
        */
    unsigned char local_mac[6] = {0};
    unsigned char local_ip[4] = {0};
    get_eth_MAC(argv[1], local_mac);
    get_eth_IP(argv[1], local_ip);

    //DLC HEADER填充
    memcpy(arp_pck.dlc_src_mac, local_mac, 6);
    memcpy(arp_pck.dlc_dst_mac, brd_mac, 6);
    arp_pck.dlc_frame = htons(ETH_P_ARP);

    //arp 包填充
    arp_pck.arp_hwtype = htons(0x0001);
    arp_pck.arp_protype = htons(ETH_P_IP);
    arp_pck.arp_hwlen  = 6;
    arp_pck.arp_prolen = 4;
    arp_pck.arp_op = htons(0x0001);
    memcpy(arp_pck.arp_src_mac, local_mac, 6);
    memcpy(arp_pck.arp_src_ip, local_ip, 4);
    memcpy(arp_pck.arp_dst_mac, brd_mac, 6);
    //memcpy(arp_pck.arp_dst_ip, dst_ip, 4);
    memcpy(arp_pck.arp_dst_ip, ip, 4);

    //struct sockaddr_ll
    struct sockaddr_ll eth_in;
    bzero(&eth_in, sizeof(eth_in));
    eth_in.sll_family = PF_PACKET;
    printf("index=%d\n", eth_in.sll_ifindex = if_nametoindex(argv[1]) );

    //raw_socket
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP) );
    if(sockfd < 0){
            perror("socket");
            return 0;}
    printf("sockfd=%d\n", sockfd);
    int ret = sendto(sockfd, &arp_pck, sizeof(arp_pck), 0, (struct sockaddr *)&eth_in, sizeof(eth_in) );
    if(ret < 0){
            perror("sendto");
            printf("errno=%d\n", errno);}

    return 0;
}

int get_eth_MAC(char *eth_name, unsigned char *MAC){
    struct ifreq ifr;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0)
    {
        perror("socket");
        return sock_fd;
    }
    strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

    int ret_ioctl = ioctl(sock_fd, SIOCGIFHWADDR, &ifr);
    if(ret_ioctl < 0)
    {
        perror("ioctl");
        return ret_ioctl;
    }

    int i = 0;
        for(i = 0 ; i < 14; i++)
    {
        printf("%02x\t",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    }
    printf("\n");
    memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
    close(sock_fd);
    return 0;}

int get_eth_IP(char *eth_name, unsigned char *IP){
    struct ifreq ifr;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0)
    {
        perror("socket");
        return sock_fd;
    }
    strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

    int ret_ioctl = ioctl(sock_fd, SIOCGIFADDR, &ifr);
    if(ret_ioctl < 0)
    {
        perror("ioctl");
        return ret_ioctl;
    }
    int i = 0;
    for(i = 0; i < 14; i++)
    {
        printf("%d\t", (unsigned char)ifr.ifr_addr.sa_data[i]);
    }
    printf("\n");
    memcpy(IP, ifr.ifr_addr.sa_data+2, 4);
    close(sock_fd);
    return 0;}

int get_eth_broadaddr(char *eth_name, unsigned char *broadaddr){

    struct ifreq ifr;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock_fd < 0)
    {
        perror("socket");
        return sock_fd;
    }
    strncpy(ifr.ifr_name,(char *)eth_name, sizeof(ifr.ifr_name) );

    int ret_ioctl = ioctl(sock_fd, SIOCGIFBRDADDR, &ifr);
    int i = 0;
    for(i = 0; i < 14; i++)
    {
        printf("%d\t", (unsigned char)ifr.ifr_broadaddr.sa_data[i]);
    }
    printf("\n");
    memcpy(broadaddr, ifr.ifr_broadaddr.sa_data+2, 4);

    close(sock_fd);
    return 0;}

int change_InputIpForm(char *ipc){
      int i = 0;
      char *pStart = ipc;
      char *pEnd = ipc;
      //总处理
      while (*pEnd != '\0'){
        while (*pEnd!='.' && *pEnd!='\0') {
          pEnd++; }   //以.分割处理
        ip[i] = 0;
        for (pStart; pStart!=pEnd; ++pStart){ 
          ip[i] = ip[i] * 10 + *pStart - '0'; }  //字符变换数值
        if (*pEnd == '\0')
          break;
        pStart = pEnd + 1;
        pEnd++;
        i++;
      }
        /*
        for (int i = 0; i < 4; ++i){
                printf("%d ", ip[i]);}    //打印检测
            */
        return ip[4];}
