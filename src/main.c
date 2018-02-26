/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"
#include "tracelog.h"

uint8_t DebugMark = 0;
uint8_t	udp_server_ip[4] = {202, 38, 210, 131};	// ip address
uint8_t	ip[4] = {0};	// ip address
uint8_t	dns[4] = {222, 201, 130, 30};
uint8_t	MAC[6] = {0};
// 反正这里后面都是0应该没什么问题吧。。。（Flag
unsigned char		UserName[32] = {0};
unsigned char		Password[32] = {0};
unsigned char		DeviceName[IFNAMSIZ] = "eth0";
unsigned char		HostName[32] = {0};
unsigned char		Version[64] = {0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a};
int					Version_len = 9;
unsigned char		Hash[64] = {0x2e, 0xc1, 0x5a, 0xd2, 0x58, 0xae, 0xe9, 0x60, 0x4b, 0x18, 0xf2, 0xf8, 0x11, 0x4d, 0xa3, 0x8d, 0xb1, 0x6e, 0xfd, 0x00};

unsigned char		ipaddr[16] = {0};
unsigned char		udp_server_ipaddr[16] = "202.38.210.131";

void PrintHelp(const char * argn)
{
	printf("Usage: %s --username <username> --password <password> [options...]\n"
		" -f, --iface <ifname>\n"
		" -n, --dns <dns>\n"
		" -t, --hostname <hostname>\n"
		" -s, --udp-server <server>\n"
		" -c, --cli-version <client version>\n"
		" -h, --hash <hash>\n"
		" -D, --debug\n"
		" -o, --logoff\n",
		argn);
}

int main(int argc, char *argv[])
{
	int client = 1;
	int ch;
	uint8_t buf[128];

	// see info.h for more about long_options
	while ((ch = getopt_long(argc, argv, "u:p:f:m:a:k:g:n:t:s:c:h:oD",
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
		case 'D':
			DebugMark = 1;
		break;
		case 'o':
			client = LOGOFF;
		break;
		default:
			PrintHelp(argv[0]);
			exit(-1);
		break;
		}
	}

	LogWrite(INF,"%s","##################################");
	LogWrite(INF,"%s","Powered by Scutclient Project");
	LogWrite(INF,"%s","Contact us with QQ group 262939451");
	LogWrite(INF,"%s","##################################");

	if(HostName[0] == 0) {
		gethostname(HostName, sizeof(HostName));
	}

	if((GetIPOfDevice(DeviceName, (uint32_t*)ip) < 0) && (client != LOGOFF))
	{
		exit(-1);
	}

	snprintf(ipaddr, sizeof(ipaddr), "%hhd.%hhd.%hhd.%hhd", ip[0], ip[1], ip[2], ip[3]);
	GetMacOfDevice(DeviceName, MAC);
	/* 调用子函数完成802.1X认证 */
	Authentication(client);

	return 0;
}
