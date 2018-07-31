# ARP_sed_rev
在Android通过ARP询问实现获取同一网络所有设备的MAC地址，AP隔离的网络除外

arpsed.c
编译：gcc arpsed.c -o arpsed
运行：sudo ./arpsed ens33 192.168.1.123  //ens33是网卡名，参数放在外面易于操作
交叉编译在Android上运行的程序：arm-none-linux-guneabi-gcc arpsed.c -o arpsed --static

arprev.c
编译：gcc arprev.c -o arprev
运行：sudo ./arprev ens33  //ens33是网卡名，参数放在外面易于操作
交叉编译在Android上运行的程序：
arm-none-linux-guneabi-gcc arprev.c -o arprev --static -I /pcap_include/ -lpcap
pcap_include是pcap.h库，-lpcap 是要自己使用交叉工具变成适用于Android的libpcap.a库

动态库：libpcap.so
静态库：libpcap.a

接收数据包的程序有段错误，经调试后已解决，查看指针packet的

无限循环程序似乎不能重定向信息，所以设置了接收300个数据包就结束

任务基本完成，之后的就是待优化了


