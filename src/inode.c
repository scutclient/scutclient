#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h>
//#define PRINTINFO 1


void SendiNodeStartPkt();
void SendiNodeLogoffPkt();
void SendiNodeResponseIdentity(const uint8_t request[]);
void SendiNodeResponseMD5(const uint8_t request[]);
void SendiNodeResponseAllocated(const uint8_t request[]);
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

void SendiNodeStartPkt()
{
	// Fill Ethernet header
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x01;	// Type=Start
	Packet[16] = 0x00;// Length=0x0000
	Packet[17] = 0x00;
	memcpy(Packet, MultcastAddr, 6);
	packetlen=64;

#ifdef PRINTINFO
printf("\n*****************iNode Start info***************************\n");
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

void SendiNodeResponseIdentity(const uint8_t request[])
{
	size_t packetlen;
	uint16_t eaplen;
	// Fill Ethernet header
	memcpy(Packet, EthHeader,14);
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空
	Packet[18] = /*(EAP_Code)*/ RESPONSE;	// Code
	Packet[19] = request[19];		// ID
	//Packet[20~21]留空			// Length
	Packet[22] = /*(EAP_Type)*/ IDENTITY;	// Type
	// Type-Data
	packetlen = 23;
	Packet[packetlen++] = 0x15;	  // 上传IP地址
	Packet[packetlen++] = 0x04;	  //
	memcpy(Packet+packetlen, ip, 4);//
	packetlen += 4;			  //
	Packet[packetlen++] = 0x06;		  // 携带版本号
	Packet[packetlen++] = 0x07;		  //
	FillBase64Area((char*)Packet+packetlen);//
	packetlen += 28;			  //
	Packet[packetlen++] = ' '; // 两个空格符
	Packet[packetlen++] = ' '; //
	//末尾添加用户名
	memcpy(Packet+packetlen, UserName, userlen);
	packetlen += userlen;
	// 补填前面留空的两处Length
	eaplen = htons(packetlen-18);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));
	memcpy(Packet+20, &eaplen, sizeof(eaplen));

#ifdef PRINTINFO
printf("\n*****************iNode Identity info***************************\n");
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

void SendiNodeResponseMD5(const uint8_t request[])
{
	uint16_t eaplen;
	uint8_t  Packet[128];
	packetlen = 14+4+22+userlen; // ethhdr+EAPOL+EAP+userlen
	// Fill Ethernet header
	memcpy(Packet, EthHeader,14);
	// 802,1X Authentication
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空
	memcpy(Packet+16, &eaplen, sizeof(eaplen));	// Length
	// Extensible Authentication Protocol
	Packet[18] = /*(EAP_Code)*/ RESPONSE;// Code
	Packet[19] = request[19];	// ID
	//Packet[20~21]留空
//
	Packet[22] = /*(EAP_Type)*/ MD5;	// Type
	Packet[23] = 16;		// Value-Size: 16 Bytes
	FillMD5Area(Packet+24, request[19], Password, request+24);
	packetlen = 40;
	//末尾添加用户名
	memcpy(Packet+packetlen, UserName, userlen);
	// 补填前面留空的两处Length
	eaplen = htons(22+userlen);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));
	memcpy(Packet+20, &eaplen, sizeof(eaplen));
	packetlen = 60;
#ifdef PRINTINFO
printf("\n*****************iNode MD5 info***************************\n");
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

void SendResponseAllocated(const uint8_t request[])
{
	uint16_t eaplen;
	int passwdlen;
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
	Packet[22] = /*(EAP_Type)*/ ALLOCATED;	// Type
	// Type-Data
	packetlen = 23;
	Packet[packetlen++] = 0x0c;	  // 
	//末尾添加用户名
	memcpy(Packet+packetlen, UserName, userlen);
	packetlen += userlen;
	//末尾添加Password
	passwdlen = strlen(Password); 
	memcpy(Packet+packetlen, Password, passwdlen);
	packetlen += passwdlen;
	// 补填前面留空的两处Length
	eaplen = htons(packetlen-18);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));
	memcpy(Packet+20, &eaplen, sizeof(eaplen));
	packetlen = 60;
#ifdef PRINTINFO
printf("\n*****************iNode Allocated info***************************\n");
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

void SendiNodeLogoffPkt()
{
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x02;	// Type=Logoff
	Packet[16] = Packet[17] =0x00;// Length=0x0000
	// 发包
	packetlen = 18 ;

#ifdef PRINTINFO
printf("\n*****************iNode Logoff info***************************\n");
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

