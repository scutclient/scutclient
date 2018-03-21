/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"
#include "tracelog.h"
#include <signal.h>

struct sigaction sa_term;
struct in_addr local_ipaddr;
struct in_addr udpserver_ipaddr;
struct in_addr dns_ipaddr;
uint8_t MAC[6];
// 反正这里后面都是0应该没什么问题吧。。。（Flag
char *UserName;
char *Password;
char *HookCmd;
char DeviceName[IFNAMSIZ] = "eth0";
char HostName[32];
char *Hash = "2ec15ad258aee9604b18f2f8114da38db16efd00";
unsigned char Version[64] = { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0x96, 0x02, 0x2a };
int Version_len = 9;

void PrintHelp(const char * argn) {
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

void handle_term(int signal) {
	LogWrite(INF, "Exiting...");
	auth_8021x_Logoff();
	exit(0);
}

int main(int argc, char *argv[]) {
	int client = 1;
	int ch, tmpdbg;
	uint8_t buf[128];

	// see info.h for more about long_options
	while ((ch = getopt_long(argc, argv, "u:p:E:f:m:a:k:g:n:t:s:c:h:oD::",
			long_options, NULL)) != -1) {
		switch (ch) {
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
			if (!inet_aton(optarg, &dns_ipaddr)) {
				LogWrite(ERROR, "DNS invalid!");
				exit(-1);
			}
			break;
		case 't':
			strcpy(HostName, optarg);
			break;
		case 's':
			if (!inet_aton(optarg, &udpserver_ipaddr)) {
				LogWrite(ERROR, "UDP server IP invalid!");
				exit(-1);
			}
			break;
		case 'c':
			hexStrToByte(optarg, buf, strlen(optarg));
			Version_len = strlen(optarg) / 2;
			memcpy(Version, buf, Version_len);
			break;
		case 'h':
			Hash = optarg;
			break;
		case 'D':
			if (optarg) {
				tmpdbg = atoi(optarg);
				if ((tmpdbg < NONE) || (tmpdbg > TRACE)) {
					LogWrite(ERROR, "Invalid debug level!");
				} else {
					cloglev = tmpdbg;
				}
			} else {
				cloglev = DEBUG;
			}
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

	LogWrite(INF, "##################################");
	LogWrite(INF, "Powered by Scutclient Project");
	LogWrite(INF, "Contact us with QQ group 262939451");
	LogWrite(INF, "##################################");

	if (HostName[0] == 0)
		gethostname(HostName, sizeof(HostName));

	if (client != LOGOFF) {
		if (GetIPOfDevice(DeviceName, &(local_ipaddr.s_addr)) < 0)
			exit(-1);
		if (!(UserName && Password && UserName[0] && Password[0])) {
			LogWrite(ERROR, "Please specify username and password!");
			exit(-1);
		}
		if (udpserver_ipaddr.s_addr == 0)
			inet_aton(SERVER_ADDR, &udpserver_ipaddr);
		if (dns_ipaddr.s_addr == 0)
			inet_aton(DNS_ADDR, &dns_ipaddr);
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
