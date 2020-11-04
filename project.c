#include<stdio.h>	//For standard things
#include<stdlib.h>	//malloc
#include<string.h>	//memset
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>	//sifreq
#include <unistd.h>	//close
#include <limits.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include </home/mszostu/msgbuf.h>
#include <stdbool.h>


void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void print_udp_packet(unsigned char * , int);
void print_icmp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);

int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;


int main()
{
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); 
	
	logfile=fopen("/home/mszostu/nowy.txt","w");
	if(logfile==NULL) printf("Unable to create file.");
	printf("Starting...\n");
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;

		data_size = recvfrom(sock_raw , buffer , 1024 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		tablicaKlas(buffer, data_size);
		ProcessPacket(buffer , data_size);
	} 

	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
	// generacja wskaznika iph
	struct iphdr *iph = (struct iphdr*)buffer;
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			//PrintIcmpPacket(Buffer,Size);
			//checkIncomingPackets();
			print_icmp_packet(buffer, size);
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
}


void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	unsigned char tosbits;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;


	tosbits = iph->tos;
	fprintf(logfile,"\n");
	fprintf(logfile,"IP Header\n");
	fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(logfile,"   |-The ToS bits are [DSCP]  : %d\n",tosbits);
	fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));

	fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(logfile,"   |-Source IP             : %s\n",inet_ntoa(source.sin_addr));
	fprintf(logfile,"   |-Destination IP        : %s\n",inet_ntoa(dest.sin_addr));


}

void print_icmp_packet(unsigned char* Buffer , int Size)
{

	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);
			
	fprintf(logfile,"\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile,"\n");
		

	print_icmp_packet_address(Buffer, Size);
	packetNumber();
	fprintf(logfile,"\n###########################################################");
}

void PrintDataIcmp (unsigned char* data , int Size)
{
			int counter = 1;
	for(i=0 ; i < Size ; i++)

	{

		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) {
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				}

				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			    

			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);


		if(counter == Size) { // which byte is DSCP
		// dscp
	
		//fprintf(logfile,"[DSCP: 0x%02X]",(unsigned int)data[i+1]); // break przed samym polem DSCP
		int nval = (unsigned int)data[1];
		fprintf(logfile,"\nDSCP field: 0x0%d\n", nval);
		//break; // break przed samym polem DSCP
		
		//	
		}

		
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}
	counter++;
	int counter = counter - 82;
	//fprintf(logfile,"\nDSCP field: 0x0%d", nval);
	}


}


void PrintData (unsigned char* data , int Size)
{
	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfile,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfile,"."); //otherwise print a dot
			}
			fprintf(logfile,"\n");
		} 
		
		if(i%16==0) fprintf(logfile,"   ");
			fprintf(logfile," %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
			
			fprintf(logfile,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
				else fprintf(logfile,".");
			}
			fprintf(logfile,"\n");
		}

	}
	unsigned short iphdrlen;
	unsigned char tosbits;


}
void print_icmp_packet_address(unsigned char* Buffer , int Size) {
//	char *waz;
//	waz = &iph;
//	fprintf (logfile, "IP header is at memory location: %08x\n", &waz);

	int i; 
  	for (i =0; i<Size; i++) {
	 //fprintf(logfile, "Buffer array elemetn number: %d", i)	
	 fprintf(logfile, "\n");
	 fprintf (logfile,"Buffer arr element no: %d \n", i);	  
     fprintf(logfile,"Virtual memory address: %p\n", &Buffer[i]);
     char *b;
     b = &Buffer[i];
	 //fprintf(logfile, "\n");
	 fprintf(logfile, "Value stored at virtual memory address %p is %d [in DEC] ", b, *b);
	 fprintf(logfile, "\n");
     //fprintf(logfile, "This is BUFF: %s",b); // string literal, not a variable error fix
     printf("\n");
  } 



//	int *b;
//	b = &iph;
//	fprintf(logfile, "The values tored at address %p is %d\n", b, *b);
}
int icmpPacketCounter = 1;
void packetNumber ()
{
		fprintf (logfile,"Packet no: %d \n", icmpPacketCounter);
		icmpPacketCounter++;
	//	int counter = 1;

}
void incremento(int *n){
  (*n)++;
}

	int liczbaPolaczen = 10; //na razie z gory ustalone 10, potem z GTK zaciagane

	int liczbaPortowWyjsciowych = 10; // narazie z gory ustalone 10, potem z GTK zaciagane

	int liczbaKlas = 5; // narazie z gory ustalone 10, potem z GTK zaciagane

	int ostatniaKartaOdczyt; // zawiera infomacje o tym, z ktorej karty wzieto pakiet


void tablicaKlas (unsigned char* Buffer, int Size){

typedef struct {
		int klasa;
		unsigned char tosbits;
}klasa;

	struct klasa *tablica_klas = malloc(liczbaKlas*sizeof(klasa));

}

void tablicaPakietowOdczytanych () {

unsigned int *liczba_pakietow_odczytanych = malloc(liczbaPortowWyjsciowych*sizeof(liczba_pakietow_odczytanych));

}

void kartaMaPrzerwanie () {

	bool *karta_ma_przerwanie = malloc(liczbaPortowWyjsciowych*sizeof(kartaMaPrzerwanie));
	//Zapis true lub false do tablicy karta_ma_przerwanie

	//Wybrana jest ta karta, z której pobranonajmniej pakietów 
	//i nie była ostatniowybraną kartą, 
	//jeśli więcej niż jedna kartawygenerowała przerwanie
}


void tablicaPolaczen (unsigned char* Buffer, int Size) {

	// getting destination IP address
	long unsigned int dstIpAddress = htonl(dest.sin_addr.s_addr);

	// getting source IP address
	long unsigned int srcIpAddress = htonl(source.sin_addr.s_addr);

	// 3232235719 = 192.168.0.199
	// 3232235691 = 192.168.0.171
	// 3232235718 = 192.168.0.198

	typedef struct polaczenia 
	{
		unsigned int dstIpAddress;
		unsigned int srcIpAddress;
	}polaczenia;

	struct polaczenia *tablica_polaczen = malloc(liczbaPolaczen*sizeof(polaczenia));

	tablica_polaczen[0].dstIpAddress = 3232235719;
	tablica_polaczen[1].dstIpAddress = 3232235691;
	tablica_polaczen[2].dstIpAddress = 3232235718;

	tablica_polaczen[0].srcIpAddress = 3232235691;
	tablica_polaczen[1].srcIpAddress = 3232235719;
	tablica_polaczen[2].srcIpAddress = 3232235718;

	int cnt;
	int failCnt = 1;
	for (cnt =0; cnt< 3; cnt++){

		if ((dstIpAddress == tablica_polaczen[cnt].dstIpAddress) && (srcIpAddress == tablica_polaczen[cnt].srcIpAddress)) {
			fprintf(logfile, "Index that belong to connections table: %d\n", cnt);
		} else {
			fprintf(logfile, "Index that not belong to connections table: %d\n", cnt);
			failCnt++;
		}
	}
	if (failCnt == 3){ // it means that packet with such dst and src address does not exits in connections table
		free(Buffer); // buffer memory is free
	}

	int port_wyjsciowy;
	struct port_wyjsciowy
	{
		int port_wyjsciowy;
		unsigned int dstIpAddress;
	};

	//int cnt;
	for (cnt =0; cnt< 3; cnt++){

		if (tablica_polaczen[0].dstIpAddress = 3232235719) {
			port_wyjsciowy = 1;
			fprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} else if (tablica_polaczen[0].dstIpAddress = 3232235718) {
			port_wyjsciowy = 2;
			ffprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} else if (tablica_polaczen[0].dstIpAddress = 3232235691) {
			port_wyjsciowy = 3;
			fprintf(logfile, "Output port is %d\n", port_wyjsciowy);
			break;
		} 

	}
}
void odczytajTosBits (unsigned char* Buffer, int Size) {
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	unsigned char tosbits = (unsigned int)iph->tos;

}

