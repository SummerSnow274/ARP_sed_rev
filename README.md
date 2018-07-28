# ARP_sed_rev
在Android通过ARP询问实现获取同一网络所有设备的MAC地址，AP隔离的网络除外

arpsed.c
编译：gcc arpsed.c -o arpsed
运行：sudo ./arpsed ens33 192.168.1.123  //ens33是网卡名，参数放在外面易于操作


