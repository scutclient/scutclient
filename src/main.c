/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"
#include "tracelog.h"
#include <signal.h>

struct sigaction sa_term;
uint8_t DebugMark = 0;
struct in_addr local_ipaddr;
uint8_t	udp_server_ip[4] = {202, 38, 210, 131};	// ip address
uint8_t	dns[4] = {222, 201, 130, 30};
uint8_t	MAC[6] = {0};
// 反正这里后面都是0应该没什么问题吧。。。（Flag
char *UserName;
char *Password;
char *HookCmd;
char DeviceName[IFNAMSIZ] = "eth0";
unsigned char		HostName[32] = {0};
unsigned char		Version[64] = {0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a};
int					Version_len = 9;
unsigned char		Hash[64] = "2ec15ad258aee9604b18f2f8114da38db16efd00";

unsigned char		udp_server_ipaddr[16] = "202.38.210.131";

void PrintHelp(const char * argn)
{
	printf("Usage: %s --username <username> --password <password> [options...]\n"
		" -f, --iface <ifname> Interface to perform authentication.\n"
		" -n, --dns <dns> DNS server address to be sent to UDP server.\n"
		" -t, --hostname <hostname>\n"
		" -s, --udp-server <server>\n"
		" -c, --cli-version <client version>\n"
		" -h, --hash <hash> DrAuthSvr.dll hash value.\n"
		" -E, --auth-exec <command> Command to be execute after EAP authentication success.\n"
		" -D, --debug\n"
		" -o, --logoff\n",
		argn);
}

void handle_term(int signal)
{
	LogWrite(INF, "Exiting...");
	auth_8021x_Logoff();
	exit(0);
}

int main(int argc, char *argv[])
{
	int client = 1;
	int ch;
	uint8_t buf[128];

	// see info.h for more about long_options
	while ((ch = getopt_long(argc, argv, "u:p:E:f:m:a:k:g:n:t:s:c:h:oD",
									long_options, NULL)) != -1) {
		switch(ch) {
		case 'u':
			UserName = optarg;
		break;
		case 'p':
			Password = optarg;
		break;
		case 'E':
			HookCmd = optarg;
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

	if(HostName[0] == 0)
		gethostname(HostName, sizeof(HostName));

	if (client != LOGOFF)
	{
		if(GetIPOfDevice(DeviceName, &(local_ipaddr.s_addr)) < 0)
			exit(-1);
		if(!(UserName && Password && UserName[0] && Password[0]))
		{
			LogWrite(ERROR,"%s","Please specify username and password!");
			exit(-1);
		}
	}

	GetMacOfDevice(DeviceName, MAC);

	/* 配置退出登录的signal handler */
	sa_term.sa_handler = &handle_term;
	sa_term.sa_flags = SA_RESETHAND;
	sigfillset(&sa_term.sa_mask);
	sigaction(SIGTERM, &sa_term, NULL);
	sigaction(SIGINT, &sa_term, NULL);

	/* 调用子函数完成802.1X认证 */
	Authentication(client);

	return 0;
}
