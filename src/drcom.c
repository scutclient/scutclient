#include "drcom.h"
#include "functions.h"
#include "info.h"

extern struct in_addr local_ipaddr;
extern uint8_t MAC[6];

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef enum {MISC_0800=0x08, ALIVE_FILE=0x10, MISC_3000=0x30, MISC_2800=0x28} DRCOM_Type;

static uint8_t crc_md5_info[16];
static int drcom_package_id = 0;  // 包的id，每次自增1
char drcom_misc1_flux[4];
char drcom_misc3_flux[4];
uint8_t timeNotAllowed = 0;
uint8_t tailinfo[16];

uint32_t drcom_crc32(uint8_t *data, int data_len) {
	uint32_t ret = 0;
	int i;
	for (i = 0; i < data_len; i += 4) {
		ret ^= *(unsigned int *) (data + i);
		ret &= 0xFFFFFFFF;
	}

	// 大端小端的坑
	ret = htole32(ret);
	ret = (ret * 19680126) & 0xFFFFFFFF;
	ret = htole32(ret);

	return ret;
}

void encryptDrcomInfo(unsigned char *info) {
	int i;
	unsigned char *chartmp = NULL;
	chartmp = (unsigned char *) malloc(16);
	for (i = 0; i < 16; i++) {
		chartmp[i] = (unsigned char) ((info[i] << (i & 0x07))
				+ (info[i] >> (8 - (i & 0x07))));
	}
	memcpy(info, chartmp, 16);
	free(chartmp);
}

size_t AppendDrcomStartPkt(uint8_t *EthHeader, uint8_t *Packet) {
	size_t packetlen = 0;
	LogWrite(DRCOM, DEBUG, "Preparing Start packet...");
	memset(Packet, 0x00, 97);  //fill 0x00
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader, 14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x01;	// Type=Start
	Packet[16] = 0x00;	// Length=0x0000
	Packet[17] = 0x00;
	packetlen = 96;

	return packetlen;
}

size_t AppendDrcomResponseIdentity(const uint8_t *request, uint8_t *EthHeader,
		const char *UserName, uint8_t *Packet) {
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);

	LogWrite(DRCOM, DEBUG, "Preparing Dr.com identity...");
	memset(Packet, 0x00, 97);	//fill 0x00
	uint16_t eaplen;
	// Fill Ethernet header
	memcpy(Packet, EthHeader, 14);
	// 802,1X Authentication
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空	// Length
	// Extensible Authentication Protocol
	Packet[18] = /*(EAP_Code)*/RESPONSE;	// Code
	Packet[19] = request[19];		// ID
	//Packet[20~21]留空			// Length
	Packet[22] = /*(EAP_Type)*/IDENTITY;	// Type
	//fill username and ip
	packetlen = 23;
	memcpy(Packet + packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x44;
	Packet[packetlen++] = 0x61;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x0;

	memcpy(Packet + packetlen, (char *) (&local_ipaddr.s_addr), 4);
	packetlen += 4;
	if (packetlen < 96) {
		packetlen = 96;
	}
	// 补填前面留空的两处Length
	eaplen = htons(userlen + 14);
	memcpy(Packet + 16, &eaplen, sizeof(eaplen));
	eaplen = htons(userlen + 14);
	memcpy(Packet + 20, &eaplen, sizeof(eaplen));

	return packetlen;
}

size_t AppendDrcomResponseMD5(const uint8_t *request, uint8_t *EthHeader,
		const char *UserName, const char *Password, uint8_t *Packet) {
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);
	uint16_t eaplen = 0;

	LogWrite(DRCOM, DEBUG, "Preparing Dr.com MD5 response...");
	memset(Packet, 0x00, 97);	//fill 0x00

	// Fill Ethernet header
	memcpy(Packet, EthHeader, 14);

	// 802,1X Authentication
	Packet[14] = 0x1;	// 802.1X Version 1
	Packet[15] = 0x0;	// Type=0 (EAP Packet)
	//Packet[16~17]留空	// Length
	// Extensible Authentication Protocol
	Packet[18] = /*(EAP_Code)*/RESPONSE;	// Code
	Packet[19] = request[19];	// ID
	//Packet[20~21]留空	
	Packet[22] = /*(EAP_Type)*/MD5;	// Type
	Packet[23] = 0x10;		// Value-Size: 16 Bytes
	packetlen = 24;
	FillMD5Area(Packet + packetlen, request[19], Password, request + 24);
	// // 存好md5信息，以备后面udp报文使用
	memcpy(crc_md5_info, Packet + packetlen, 16);
	packetlen += 16;
	memcpy(Packet + packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x44;
	Packet[packetlen++] = 0x61;
	Packet[packetlen++] = 0x2a;
	Packet[packetlen++] = 0x0;
	memcpy(Packet + packetlen, (char *) (&local_ipaddr.s_addr), 4);  // 填充ip
	packetlen += 4;
	// 补填前面留空的两处Length
	eaplen = htons(userlen + 31);
	memcpy(Packet + 16, &eaplen, sizeof(eaplen));	// Length
	eaplen = htons(userlen + 31);
	memcpy(Packet + 20, &eaplen, sizeof(eaplen));	// Length

	if (packetlen < 96) {
		packetlen = 96;
	}

	return packetlen;
}

size_t AppendDrcomLogoffPkt(uint8_t *EthHeader, uint8_t *Packet) {
	size_t packetlen = 0;
	memset(Packet, 0xa5, 97);	//fill 0xa5
	// Ethernet Header (14 Bytes)
	memcpy(Packet, EthHeader, 14);
	// EAPOL (4 Bytes)
	Packet[14] = 0x01;	// Version=1
	Packet[15] = 0x02;	// Type=Logoff
	Packet[16] = 0x00;	// Length=0x0000
	Packet[17] = 0x00;
	packetlen = 96;

	return packetlen;
}

// Dr.com 802.1X 交换机认证失败Notification字符串
const char* DrcomEAPErrParse(const char *str) {
	int errcode;
	if(!strncmp("userid error", str, 12)) {
		sscanf(str, "userid error%d", &errcode);
		switch (errcode) {
			case 1:
				return "Account does not exist.";
			case 2:
			case 3:
				return "Username or password invalid.";
			case 4:
				return "This account might be expended.";
			default:
				return str;
		}
	} else if(!strncmp("Authentication Fail", str, 19)) {
		sscanf(str, "Authentication Fail ErrCode=%d", &errcode);
		switch (errcode) {
			case 0:
				return "Username or password invalid.";
			case 5:
				return "This account is suspended.";
			case 9:
				return "This account might be expended.";
			case 11:
				return "You are not allowed to perform a radius authentication.";
			case 16:
				timeNotAllowed = 1;
				return "You are not allowed to access the internet now.";
			case 30:
			case 63:
				return "No more time available for this account.";
			default:
				return str;
		}
	} else if(!strncmp("AdminReset", str, 10)) {
		return str;
	} else if(strstr(str, "Mac, IP, NASip, PORT")) {
		return "You are not allowed to login using current IP/MAC address.";
	} else if(strstr(str, "flowover")) {
		return "Data usage has reached the limit.";
	} else if(strstr(str, "In use")) {
		return "This account is in use.";
	}
	return NULL;
}

int Drcom_MISC_START_ALIVE_Setter(uint8_t *send_data, uint8_t *recv_data) {
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

int Drcom_MISC_INFO_Setter(uint8_t *send_data, uint8_t *recv_data) {
	int packetlen = 0;
	send_data[packetlen++] = 0x07;	// Code
	send_data[packetlen++] = 0x01;	//id
	send_data[packetlen++] = 0xf4;	//len(包的长度低位，一定要偶数长度的)
	send_data[packetlen++] = 0x00;	//len(244高位)
	send_data[packetlen++] = 0x03;	//step 第几步
	// 填用户名长度
	send_data[packetlen++] = strlen(UserName); //uid len  用户ID长度
	// 填MAC
	memcpy(send_data + packetlen, MAC, 6);
	packetlen += 6;
	// 填ip
	memcpy(send_data + packetlen, (char *) (&local_ipaddr.s_addr), 4);
	packetlen += 4;

	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x22;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x2a;
	// 挑战码
	memcpy(send_data + packetlen, recv_data + 8, 4);
	packetlen += 4;
	// crc32(后面再填)
	send_data[packetlen++] = 0xc7;
	send_data[packetlen++] = 0x2f;
	send_data[packetlen++] = 0x31;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x7e;	// 做完crc32后，在把这个字节置位0
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	// 填用户名
	memcpy(send_data + packetlen, UserName, strlen(UserName));
	packetlen += strlen(UserName);
	// 填计算机名
	memcpy(send_data + packetlen, HostName, 32 - strlen(UserName));
	packetlen += 32 - strlen(UserName);
	//填充32个0
	memset(send_data + packetlen, 0x00, 32);
	packetlen += 12;
	//填DNS
	memcpy(send_data + packetlen, (char *) &(dns_ipaddr.s_addr), 4);
	packetlen += 4;
	// 第2,3个DNS忽略
	packetlen += 16;

	//0x0060
	// unknow
	send_data[packetlen++] = 0x94;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	// os major
	send_data[packetlen++] = 0x06;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	// os minor
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	// os build
	send_data[packetlen++] = 0xf0;
	send_data[packetlen++] = 0x23;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	//0x0070
	// os unknown
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	// 先填充64位0x00 (在这64位里面填充Drcom版本信息)
	memset(send_data + packetlen, 0x00, 64);
	// 填充Drcom版本信息
	memcpy(send_data + packetlen, Version, Version_len);
	packetlen += 64;

	// 先填充68位0x00 (在这64位里面填充HASH信息，预留需要补0的四位)
	memset(send_data + packetlen, 0x00, 68);
	// 填充HASH信息
	memcpy(send_data + packetlen, Hash, strlen(Hash));
	packetlen += 64;
	//判定是否是4的倍数
	if (packetlen % 4 != 0) {
		//补0，使包长度为4的倍数
		packetlen = packetlen + 4 - (packetlen % 4);
	}
	// 回填包的长度
	send_data[2] = 0xFF & packetlen;
	send_data[3] = 0xFF & (packetlen >> 8);

	// 完成crc32校验
	uint32_t crc = drcom_crc32(send_data, packetlen);
	memcpy(send_data + 24, &crc, 4);
	//缓存crc32校验到crc_md5_info前4字节
	memcpy(crc_md5_info, &crc, 4);
	// 完成crc32校验，回填置位0
	send_data[28] = 0x00;
	return packetlen;
}

int Drcom_MISC_HEART_BEAT_01_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data) {
	int packetlen = 0;
	memset(send_data, 0, 40);

	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0xdc;
	send_data[packetlen++] = 0x02;

	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	memcpy(send_data + 16, drcom_misc1_flux, 4);
	packetlen = 40;

	return packetlen;
}

int Drcom_MISC_HEART_BEAT_03_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data) {
	memcpy(&drcom_misc3_flux, recv_data + 16, 4);
	memset(send_data, 0, 40);

	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x03;
	send_data[packetlen++] = 0xdc;
	send_data[packetlen++] = 0x02;

	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	memcpy(send_data + 16, drcom_misc3_flux, 4);

	memcpy(send_data + 28, (char *) (&local_ipaddr.s_addr), 4);
	packetlen = 40;

	return packetlen;
}

int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data) {
	int packetlen = 0;
	send_data[packetlen++] = 0xff;
	// 填充crc_md5_info信息
	memcpy(send_data + packetlen, crc_md5_info, 16);
	packetlen += 16;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;

	//填充MISC_3000包解密得到的tail信息
	memcpy(send_data + packetlen, tailinfo, 16);
	packetlen += 16;

	//时间信息
	time_t timeinfo = time(NULL);
	send_data[packetlen++] = 0xff & timeinfo;
	send_data[packetlen++] = 0xff & (timeinfo >> 8);
	return packetlen;
}

