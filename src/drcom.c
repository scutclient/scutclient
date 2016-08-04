#include "drcom.h"
#include "functions.h"

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef enum {MISC_0800=0x08, ALIVE_FILE=0x10, MISC_3000=0x30, MISC_2800=0x28} DRCOM_Type;

static uint8_t crc32sum[4] = {0};
static uint8_t md5info[16] = {0};
static int drcom_package_id = 0;  // 包的id，每次自增1

unsigned int drcom_crc32(char *data, int data_len)
{
	unsigned int ret = 0;
	int i = 0;
	for ( i = 0; i < data_len;i += 4) 
	{
		ret ^= *(unsigned int *) (data + i);
		ret &= 0xFFFFFFFF;
	}
	return ret;
}

size_t SendDrcomStartPkt( uint8_t EthHeader[], uint8_t *Packet )
{
	size_t packetlen = 0;
	memset(Packet, 0x00,97);//fill 0x00
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x01;	// Type=Start
	Packet[16] = 0x00;// Length=0x0000
	Packet[17] = 0x00;
	packetlen=96;

	PrintDebugInfo(	"Start", Packet, packetlen);

	return packetlen;
}

size_t SendDrcomResponseIdentity(const uint8_t request[], uint8_t EthHeader[], unsigned char *UserName, uint8_t *Packet )
{
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);
	memset(Packet, 0x00,97);//fill 0x00
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
	//fill username and ip
	packetlen = 23;
	memcpy(Packet+packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x44;
	Packet[packetlen++] = 0x61;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x0;
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	memcpy(Packet+packetlen, ip, 4);
	packetlen += 4;
	if(packetlen < 96)
	{
		packetlen = 96;
	}
	// 补填前面留空的两处Length
	eaplen = htons(userlen+14);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));
	eaplen = htons(userlen+14);
	memcpy(Packet+20, &eaplen, sizeof(eaplen));
	
	PrintDebugInfo(	"Identity", Packet, packetlen);

	return packetlen;
}

size_t SendDrcomResponseMD5(const uint8_t request[],uint8_t EthHeader[], unsigned char *UserName, unsigned char *Password, uint8_t *Packet)
{
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);
	uint16_t eaplen = 0;
	memset(Packet, 0x00,97);//fill 0x00
	
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
	packetlen = 24;
	FillMD5Area(Packet+packetlen, request[19], Password, request+24);
	// 存好md5信息，以备后面udp报文使用
	memcpy(md5info,Packet+packetlen,16);
	packetlen += 16;
	memcpy(Packet+packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++]= 0x0;
	Packet[packetlen++]= 0x44;
	Packet[packetlen++]= 0x61;
	Packet[packetlen++]= 0x2a;
	Packet[packetlen++]= 0x0;
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	memcpy(Packet+packetlen, ip, 4);  // 填充ip
	packetlen += 4;
	// 补填前面留空的两处Length
	eaplen = htons(userlen+31);
	memcpy(Packet+16, &eaplen, sizeof(eaplen));	// Length
	eaplen = htons(userlen+31);
	memcpy(Packet+20, &eaplen, sizeof(eaplen));	// Length

	if(packetlen < 96)
	{
		packetlen = 96;
	}

	PrintDebugInfo(	"MD5", Packet, packetlen);

	return packetlen;
}

size_t SendDrcomLogoffPkt(uint8_t EthHeader[], uint8_t *Packet)
{
	size_t packetlen = 0;
	memset(Packet, 0xa5,97);//fill 0xa5
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader,14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x02;	// Type=Logoff
	Packet[16] = 0x00;// Length=0x0000
	Packet[17] = 0x00;
	packetlen=96;

	PrintDebugInfo(	"Logoff", Packet, packetlen);

	return packetlen;
}

int Drcom_LOGIN_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x08;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	return packetlen;
}

int Drcom_ALIVE_LOGIN_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0xf4;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x03;
	send_data[packetlen++] = 0x0c;
	// 填MAC
	uint8_t MAC[6]= {0};
	GetMacFromDevice(MAC);
	memcpy(send_data+packetlen, MAC, 6);
	packetlen += 6;
		// 填ip
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	memcpy(send_data+packetlen, ip, 4);
	packetlen += 4;
	
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x22;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x2a;
	// 挑战码
	memcpy(send_data+packetlen, recv_data+8, 4);
	packetlen += 4;
	
	send_data[packetlen++] = 0xc7;
	send_data[packetlen++] = 0x2f;
	send_data[packetlen++] = 0x31;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x7e;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	// 先填充80位0x00 (在这80位里面填充用户名和计算机名)
	memset(send_data+packetlen,0x00,80);
	// 填用户名
	unsigned char username[32] = {0};
	GetUserName(username);
	memcpy(send_data+packetlen, username, strlen(username));
	packetlen += strlen(username);
	// 填计算机名
	unsigned char hostname[32] = {0};
	GetHostNameFromDevice(hostname);
	memcpy(send_data+packetlen, hostname, strlen(hostname));
	packetlen += (80 - strlen(username));
	
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x01;
	
	// 先填充64位0x00 (在这64位里面填充Drcom版本信息)
	memset(send_data+packetlen,0x00,64);
	// 填充Drcom版本信息
	unsigned char version[64] = {0};
	int len = GetVersionFromDevice(version);
	memcpy(send_data+packetlen, version, len);
	packetlen += 64;
	
	// 先填充64位0x00 (在这64位里面填充HASH信息)
	memset(send_data+packetlen,0x00,64);
	// 填充HASH信息
	unsigned char hash[64] = {0};
	GetHashFromDevice(hash);
	memcpy(send_data+packetlen, hash, strlen(hash));
	packetlen += 64;
	
	return packetlen;
}

int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	int packetlen = 0;
	send_data[packetlen++] = 0xff;
	// 填充crc信息
	memcpy(send_data+packetlen,crc32sum,4);
	packetlen += 4;
	memcpy(send_data+packetlen,md5info+4,12);
	packetlen += 12;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x44;
	send_data[packetlen++] = 0x72;
	send_data[packetlen++] = 0x63;
	send_data[packetlen++] = 0x6f;
	
	//填充udp认证服务器的ip
	uint8_t server_ip[4]= {0};
	GetUdpServerIpFromDevice(server_ip);
	memcpy(send_data+packetlen,server_ip,4);
	packetlen += 4;
	
	srand((unsigned)time(NULL)); /*随机种子*/
	// 随机端口
	uint16_t server_port=rand()%100+18000; /*为18000-18100之间的随机数*/
	memcpy(send_data+packetlen,&server_port,2);
	packetlen += 2;
	
	//填充本机的ip
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	memcpy(send_data+packetlen,ip,4);
	packetlen += 4;
	
	// 随机端口
	uint16_t port=rand()%10+425; /*为425-435之间的随机数*/
	memcpy(send_data+packetlen,&port,2);
	packetlen += 2;
	
	//时间信息
	uint16_t timeinfo = time(NULL);
	memcpy(send_data+packetlen,&timeinfo,2);
	packetlen += 2;
	return packetlen;
}

int Drcom_MISC_2800_01_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x0f;
	send_data[packetlen++] = 0x27;
	
	// 先填充32位0x00 (在这32位里面填充随机的4个字节)
	memset(send_data+packetlen,0x00,32);
	//随机的4个字节
	srand((unsigned)time(NULL)); /*随机种子*/
	uint32_t random=rand()<<16 | rand();
	memcpy(send_data+packetlen,&random,4);
	packetlen+=32;
	return packetlen;
}

int Drcom_MISC_2800_03_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x0f;
	send_data[packetlen++] = 0x27;
	
	// 先填充16位0x00 (在这32位里面填充随机的4个字节)
	memset(send_data+packetlen,0x00,16);
	//随机的4个字节
	srand((unsigned)time(NULL)); /*随机种子*/
	uint32_t random=rand()<<16 | rand();
	memcpy(send_data+packetlen,&random,4);
	packetlen+=16;
	
	// 先填充16位0x00 (在这32位里面填充crc信息)
	memset(send_data+packetlen,0x00,16);
	//crc信息默认4个0x00，紧跟本机ip
	//填充本机的ip
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	memcpy(send_data+packetlen+4,ip,4);
	//算crc32
	unsigned int crc = (drcom_crc32(send_data, packetlen+16) * 19680126) & 0xFFFFFFFF;
	// 回填crc
	memcpy(send_data+packetlen,&crc,4);
	packetlen+=16;
	return packetlen;
}

int Drcom_HEARTBEAT_TYPE_Setter(unsigned char *send_data, char *recv_data)
{
	return Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_data, recv_data);
}
