#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h>
//#define PRINTINFO 1


void SendDigitalStartPkt();
void SendDigitalLogoffPkt();
void SendDigitalResponseIdentity(const uint8_t request[]);
void SendDigitalResponseMD5(const uint8_t request[]);
void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen);
void FillClientVersionArea(uint8_t area[20]);
void FillWindowsVersionArea(uint8_t area[20]);
void FillBase64Area(char area[]);
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[]);
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
extern pcap_t *adhandle; 
extern uint8_t Packet[255];
extern uint8_t	EthHeader[14]; // ethernet header
extern uint8_t BroadcastAddr[6]; // 广播MAC地址
extern uint8_t MultcastAddr[6]; // 多播MAC地址
extern uint8_t MAC[6];
extern char *UserName;
extern char *Password;
extern char *DeviceName;
extern size_t userlen,iplen,packetlen;
extern uint8_t	ip[4];	// ip address
extern uint8_t mask[4];
extern uint8_t gateway[4];
extern uint8_t dns[4];
extern uint8_t netinfo[46];

void SendDigitalStartPkt()
{

	memset(Packet, 0xa5,64);//fill 0xa5
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x01;	// Type=Start
	Packet[16] = 0x00;// Length=0x0000
	Packet[17] = 0x00;
	packetlen=64;

#ifdef PRINTINFO
printf("\n*****************Digital Start info***************************\n");
int m,n=0;
for(m=0;m<=packetlen-1;m++)
{
n++;
if(n==17)
{
printf("\n");
n=1;
}
printf("%02x ",Packet[m]);
}
printf("\n");
#endif

	return;
}

void SendDigitalResponseIdentity(const uint8_t request[])
{

	memset(Packet, 0x00,81);//fill 0x00
	uint16_t eaplen;
	// Fill Ethernet header
	memcpy(Packet, EthHeader,14);
	// 802,1X Authentication
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空	// Length
	// Extensible Authentication Protocol
	Packet[18] = /*(EAP_Code)*/ RESPONSE;	// Code
	Packet[19] = request[19];		// ID
	//Packet[20~21]留空			// Length
	Packet[22] = /*(EAP_Type)*/ IDENTITY;	// Type
	//fill username and netinfo
	memcpy(Packet+23, UserName, userlen);
	memcpy(Packet+23+userlen, netinfo, 46);
	// 补填前面留空的两处Length
	eaplen = htons(0x3f);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));
	eaplen = htons(0x11);
	memcpy(Packet+20, &eaplen, sizeof(eaplen));
	memcpy(Packet, MultcastAddr, 6);//多播触发
	packetlen = 81;
#ifdef PRINTINFO
printf("\n*****************Digital Identity info***************************\n");
int m,n=0;
for(m=0;m<=packetlen-1;m++)
{
n++;
if(n==17)
{
printf("\n");
n=1;
}
printf("%02x ",Packet[m]);
}
printf("\n");
#endif

	return;
}

void SendDigitalResponseMD5(const uint8_t request[])
{
	uint16_t eaplen;
	size_t   packetlen;
	memset(Packet, 0x00,214);//fill 0x00
	
	packetlen = 14+4+22+userlen; // ethhdr+EAPOL+EAP+userlen

	// Fill Ethernet header
	memcpy(Packet, EthHeader,14);

	// 802,1X Authentication
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空	// Length
	// Extensible Authentication Protocol
	Packet[18] = /*(EAP_Code)*/ RESPONSE;// Code
	Packet[19] = request[19];	// ID
	//Packet[20~21]留空	
	Packet[22] = /*(EAP_Type)*/ MD5;	// Type
	Packet[23] = 0x10;		// Value-Size: 16 Bytes
	FillMD5Area(Packet+24, request[19], Password, request+24);
	memcpy(Packet+168, netinfo, 46);
	
	// 补填前面留空的两处Length
	eaplen = htons(0xc4);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));	// Length
	eaplen = htons(0x96);
	memcpy(Packet+20, &eaplen, sizeof(eaplen));	// Length
	packetlen = 214;

#ifdef PRINTINFO
printf("\n*****************Digital MD5 info***************************\n");
int m,n=0;
for(m=0;m<=packetlen-1;m++)
{
n++;
if(n==17)
{
printf("\n");
n=1;
}
printf("%02x ",Packet[m]);
}
printf("\n");
#endif

	return;
}

void SendDigitalLogoffPkt()
{
	size_t packetlen;
	memset(Packet, 0xa5,64);//fill 0xa5
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x02;	// Type=Logoff
	Packet[16] = 0x00;// Length=0x0000
	Packet[17] = 0x00;
	packetlen=64;

printf("\n*****************Digital Logoff info***************************\n");
int m,n=0;
for(m=0;m<=packetlen-1;m++)
{
n++;
if(n==17)
{
printf("\n");
n=1;
}
printf("%02x ",Packet[m]);
}

	return;
}


