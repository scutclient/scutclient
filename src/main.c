/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"
#include "tracelog.h"

/* \BE\B2̬\B1\E4\C1\BF*/
uint8_t	udp_server_ip[4] = {0};	// ip address
uint8_t	ip[4] = {0};	// ip address
uint8_t	mask[4] = {0};
uint8_t	gateway[4] = {0};
uint8_t	dns[4] = {0};
uint8_t	MAC[6] = {0};
// 反正这里后面都是0应该没什么问题吧。。。（Flag
unsigned char		UserName[32] = {0};
unsigned char		Password[32] = {0};
unsigned char		DeviceName[IFNAMSIZ] = "eth0";
unsigned char		HostName[32] = {0};
unsigned char		Version[64] = {0};
int					Version_len = 0;
unsigned char		Hash[64] = {0};


unsigned char		ipaddr[16] = {0};
unsigned char		udp_server_ipaddr[16] = {0};
static unsigned char		Debug[8] = {0};



const static int LOGOFF = 0; // 下线标志位
const static int DRCOM_CLIENT = 1; // Drcom客户端标志位


int main(int argc, char *argv[])
{
	int client = 1;
	int ch;
	uint8_t buf[128];
	LogWrite(INF,"%s","##################################");
	LogWrite(INF,"%s","Powered by Scutclient Project");
	LogWrite(INF,"%s","Contact us with QQ group 262939451");
	LogWrite(INF,"%s","##################################");
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		printf("You need to be root\n");
		exit(-1);
	}

	// see info.h for more about long_options
	while ((ch = getopt_long(argc, argv, "u:p:f:m:a:k:g:n:t:s:c:h:o",
									long_options, NULL)) != -1) {
		switch(ch) {
		case 'u':
			strcpy(UserName, optarg);
		break;
		case 'p':
			strcpy(Password, optarg);
		break;
		case 'f':
			strcpy(DeviceName, optarg);
		break;
		case 'n':
			transIP(optarg, dns);
		break;
		case 't':
			strcpy(HostName, optarg);
		break;
		case 's':
			strcpy(udp_server_ipaddr, optarg);
			transIP(optarg, udp_server_ip);
		break;
		case 'c':
			hexStrToByte(optarg, buf, strlen(optarg));
			Version_len = strlen(optarg) / 2;
			memcpy(Version, buf, Version_len);
		break;
		case 'h':
			strcpy(Hash, optarg);
		break;
		case 'o':
			client = LOGOFF;
		break;
		default:
			printf("Usage:\n");
			printf("scutclient --username USERNAME --password PASSWORD --iface ethX --dns 222.201.130.30 --hostname DESKTOP-2333333 --udp-server 202.38.210.131 --cli-version 4472434f4d0096022a --hash 2ec15ad258aee9604b18f2f8114da38db16efd00");
			exit(-1);
		break;
		}

	}
	if(GetIPOfDevice(DeviceName, (uint32_t*)ip) < 0)
	{
		exit(-1);
	}
	snprintf(ipaddr, sizeof(ipaddr), "%hhd.%hhd.%hhd.%hhd", ip[0], ip[1], ip[2], ip[3]);
	GetMacOfDevice(DeviceName, MAC);
	/* 调用子函数完成802.1X认证 */
	Authentication(client);

	return 0;
}

