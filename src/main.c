/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"
#include "tracelog.h"
#include <signal.h>

struct sigaction sa_term;

// 命令行参数列表
static const struct option long_options[] = {
	{"username", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'p'},
	{"iface", required_argument, NULL, 'i'},
	{"dns", required_argument, NULL, 'n'},
	{"hostname", required_argument, NULL, 'H'},
	{"udp-server", required_argument, NULL, 's'},
	{"cli-version", required_argument,NULL, 'c'},
	{"net-time", required_argument,NULL, 'T'},
	{"hash", required_argument, NULL, 'h'},
	{"online-hook", required_argument, NULL, 'E'},
	{"offline-hook", required_argument, NULL, 'Q'},
	{"debug", optional_argument, NULL, 'D'},
	{"logoff", no_argument, NULL, 'o'},
	{NULL, no_argument, NULL, 0}
};

void PrintHelp(const char * argn) {
	printf("Usage: %s --username <username> --password <password> [options...]\n"
		" -i, --iface <ifname> Interface to perform authentication.\n"
		" -n, --dns <dns> DNS server address to be sent to UDP server.\n"
		" -H, --hostname <hostname>\n"
		" -s, --udp-server <server>\n"
		" -c, --cli-version <client version>\n"
		" -T, --net-time <time> The time you are allowed to access internet. e.g. 6:10\n"
		" -h, --hash <hash> DrAuthSvr.dll hash value.\n"
		" -E, --online-hook <command> Command to be execute after EAP authentication success.\n"
		" -Q, --offline-hook <command> Command to be execute when you are forced offline at nignt.\n"
		" -D, --debug\n"
		" -o, --logoff\n",
		argn);
}

void handle_term(int signal) {
	LogWrite(ALL, INF, "Exiting...");
	auth_8021x_Logoff();
	exit(0);
}

int main(int argc, char *argv[]) {
	LogWrite(ALL, INF, "scutclient built at: " __DATE__ " " __TIME__);
	LogWrite(ALL, INF, "Authored by Scutclient Project");
	LogWrite(ALL, INF, "Source code available at https://github.com/scutclient/scutclient");
	LogWrite(ALL, INF, "Contact us with QQ group 262939451");
	LogWrite(ALL, INF, "#######################################");
	int client = 1;
	int ch, tmpdbg;
	uint8_t a_hour = 255, a_minute = 255;
	int ret;
	unsigned int retry_time = 1;
	time_t ctime;
	struct tm * cltime;

	while ((ch = getopt_long(argc, argv, "u:p:i:n:H:s:c:T:h:E:Q:D::o",
			long_options, NULL)) != -1) {
		switch (ch) {
		case 'u':
			UserName = optarg;
			break;
		case 'p':
			Password = optarg;
			break;
		case 'E':
			OnlineHookCmd = optarg;
			break;
		case 'Q':
			OfflineHookCmd = optarg;
			break;
		case 'i':
			strncpy(DeviceName, optarg, IFNAMSIZ);
			break;
		case 'n':
			if (!inet_aton(optarg, &dns_ipaddr)) {
				LogWrite(INIT, ERROR, "DNS invalid!");
				exit(-1);
			}
			break;
		case 'H':
			strncpy(HostName, optarg, 32);
			break;
		case 's':
			if (!inet_aton(optarg, &udpserver_ipaddr)) {
				LogWrite(INIT, ERROR, "UDP server IP invalid!");
				exit(-1);
			}
			break;
		case 'T':
			if((sscanf(optarg, "%hhu:%hhu", &a_hour, &a_minute) != 2) || (a_hour >= 24) || (a_minute >= 60)) {
				LogWrite(INIT, ERROR, "Time invalid!");
				exit(-1);
			}
			break;
		case 'c':
			Version_len = hexStrToByte(optarg, Version, sizeof(Version));
			break;
		case 'h':
			Hash = optarg;
			break;
		case 'D':
			if (optarg) {
				tmpdbg = atoi(optarg);
				if ((tmpdbg < NONE) || (tmpdbg > TRACE)) {
					LogWrite(INIT, ERROR, "Invalid debug level!");
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

	if (HostName[0] == 0)
		gethostname(HostName, sizeof(HostName));

	if ((client != LOGOFF) && !((UserName && Password && UserName[0] && Password[0]))) {
		LogWrite(INIT, ERROR, "Please specify username and password!");
		exit(-1);
	}
	if (udpserver_ipaddr.s_addr == 0)
		inet_aton(SERVER_ADDR, &udpserver_ipaddr);
	if (dns_ipaddr.s_addr == 0)
		inet_aton(DNS_ADDR, &dns_ipaddr);

	/* 配置退出登录的signal handler */
	sa_term.sa_handler = &handle_term;
	sa_term.sa_flags = SA_RESETHAND;
	sigfillset(&sa_term.sa_mask);
	sigaction(SIGTERM, &sa_term, NULL);
	sigaction(SIGINT, &sa_term, NULL);

	/* 调用子函数完成802.1X认证 */
	while(1) {
		ret = Authentication(client);
		if(ret == 1) {
			retry_time = 1;
			LogWrite(ALL, INF, "Restart authentication.");
		} else if(ret == -ENETUNREACH) {
			LogWrite(ALL, INF, "Retry in %d secs.", retry_time);
			sleep(retry_time);
			if (retry_time <= 256)
				retry_time *= 2;
		} else if(timeNotAllowed && (a_minute < 60)) {
			timeNotAllowed = 0;
			ctime = time(NULL);
			cltime = localtime(&ctime);
			if(((int)a_hour * 60 + a_minute) > ((int)(cltime -> tm_hour) * 60 + cltime -> tm_min)) {
				LogWrite(ALL, INF, "Waiting till %02hhd:%02hhd. Have a good sleep...", a_hour, a_minute);
				if (OfflineHookCmd) {
					system(OfflineHookCmd);
				}
				sleep((((int)a_hour * 60 + a_minute) - ((int)(cltime -> tm_hour) * 60 + cltime -> tm_min)) * 60 - cltime -> tm_sec);
			} else {
				break;
			}
		} else {
			break;
		}
	}
	LogWrite(ALL, ERROR, "Exit.");
	return 0;
}
