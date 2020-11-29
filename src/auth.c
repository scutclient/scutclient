#include "auth.h"
#include "tracelog.h"
#include "info.h"

struct in_addr local_ipaddr;
uint8_t MAC[6];

#define DRCOM_UDP_HEARTBEAT_DELAY  12 // Drcom客户端心跳延时秒数，默认12秒
#define DRCOM_UDP_HEARTBEAT_TIMEOUT 2 // Drcom客户端心跳超时秒数
#define DRCOM_UDP_RECV_DELAY  2 // Drcom客户端收UDP报文延时秒数，默认2秒
#define AUTH_8021X_LOGOFF_DELAY 500000 // 客户端退出登录收包等待时间 0.5秒（50万微秒)
#define AUTH_8021X_RECV_DELAY  1 // 客户端收8021x报文延时秒数，默认1秒
#define AUTH_8021X_RECV_TIMES  3 // 客户端收8021x报文重试次数

/* 静态常量*/
const static uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // 广播MAC地址
const static uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // 多播MAC地址
const static uint8_t UnicastAddr[6] = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 }; // 单播MAC地址

/* 静态变量*/
static uint8_t send_8021x_data[1024]; // 用于存放发送8021x报文的变量
static size_t send_8021x_data_len = 0; // 用于存放发送8021x报文的变量的长度
static uint8_t send_udp_data[ETH_FRAME_LEN];
static uint8_t recv_udp_data[ETH_FRAME_LEN];
static int send_udp_data_len = 0; // 用于存放发送udp报文的变量的长度
static int resev = 0; // 是否收到了第一帧报文的标志位，第一帧报文用于拿到服务器的mac
static int times = AUTH_8021X_RECV_TIMES; // 8021x断链重试次数
static int success_8021x = 0; // 8021x成功登录标志位
static int isNeedHeartBeat = 0;  // 是否需要发送UDP心跳
static uint8_t EthHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x88, 0x8e };
static uint8_t BroadcastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0x8e };
static uint8_t MultcastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x80, 0xc2, 0x00, 0x00, 0x03, 0x88, 0x8e };
static uint8_t UnicastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xd0, 0xf8, 0x00, 0x00, 0x03, 0x88, 0x8e };
static time_t BaseHeartbeatTime = 0;  // UDP心跳基线时间
static int auth_8021x_sock = 0; // 8021x的socket描述符
static int auth_udp_sock = 0; // udp的socket描述符
static uint8_t lastHBDone = 1;	// 记录上次心跳是否成功结束，没有的话重拨
struct sockaddr_ll auth_8021x_addr;

/* 静态变量*/

typedef enum {
	REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10
} EAP_Code;
typedef enum {
	IDENTITY = 1,
	NOTIFICATION = 2,
	MD5 = 4,
	AVAILABLE = 20,
	ALLOCATED_0x07 = 7,
	ALLOCATED_0x08 = 8
} EAP_Type;
typedef uint8_t EAP_ID;
struct sockaddr_in serv_addr, local_addr;

int chkIfUp(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		LogWrite(INIT, ERROR, "ioctl get if_flag error: %s", strerror(errno));
		return -1;
	}
	if (ifr.ifr_ifru.ifru_flags & IFF_RUNNING) {
		LogWrite(INIT, INF, "%s link up.", DeviceName);
		return 0;
	} else {
		LogWrite(INIT, ERROR, "%s link down. Please check it.", DeviceName);
		return -1;
	}
}

int getIfIndex(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Get interface index error: %s", strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

int getIfIP(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));

	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Unable to get IP address of %s: %s", DeviceName, strerror(errno));
		return -1;
	}
	local_ipaddr = (((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr);
	return 0;
}

int getIfMAC(int sock) {
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Unable to get MAC address of %s: %s", DeviceName, strerror(errno));
		return -1;
	}
	memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int auth_8021x_Init() {
	int optv = 1;
	int ret = 0;

	// 只接受EAP的包
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (auth_8021x_sock < 0) {
		LogWrite(DOT1X, ERROR, "Unable to create raw socket: %s",
				strerror(errno));
		return auth_8021x_sock;
	}

	if ((ret = setsockopt(auth_8021x_sock, SOL_SOCKET, SO_REUSEADDR, &optv,
			sizeof(optv))) < 0) {
		LogWrite(DOT1X, ERROR, "setsockopt failed: %s", strerror(errno));
		goto ERR;
	}

	if ((ret = chkIfUp(auth_8021x_sock)) < 0) {
		goto ERR;
	}
	if ((ret = getIfMAC(auth_8021x_sock)) < 0) {
		goto ERR;
	}
	if ((ret = getIfIndex(auth_8021x_sock)) < 0) {
		goto ERR;
	}

	bzero(&auth_8021x_addr, sizeof(auth_8021x_addr));
	auth_8021x_addr.sll_ifindex = ret;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol = htons(ETH_P_PAE);
	auth_8021x_addr.sll_pkttype = PACKET_HOST;
	return 0;

ERR:
	close(auth_8021x_sock);
	return ret;
}

/*
 * 发送 EAPOL Logoff 并等待回复
 */
int auth_8021x_Logoff() {
	struct timeval timeout = { 0, AUTH_8021X_LOGOFF_DELAY };
	struct timeval tmp_timeout = timeout;
	fd_set fdR;
	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = { 0 };
	uint8_t LogoffCnt = 2;	// 发送两次
	int ret = 0;

	LogWrite(DOT1X, INF, "Client: Send Logoff.");
	// 客户端发送Logoff后，接收服务器回复
	while (LogoffCnt--) {
		send_8021x_data_len = AppendDrcomLogoffPkt(MultcastHeader, send_8021x_data);
		LogWrite(DOT1X, DEBUG, "Sending logoff packet.");
		auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
		case -1:
			LogWrite(DOT1X, ERROR, "Logoff: select socket failed: %s",
					strerror(errno));
			return -1;
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_8021x_buf)) {
					if ((EAP_Code) recv_8021x_buf[18] == FAILURE) {
						// 按照Dr.com客户端抓包结果，虽然成功退出但是两个logoff还是要发完的
						LogWrite(DOT1X, INF, "Logged off.");
						ret = 1;
					}
				}
			}
			break;
		}
	}
	return ret;
}

int auth_UDP_Init() {
	int on = 1;

	auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (auth_udp_sock < 0) {
		LogWrite(DRCOM, ERROR, "Create UDP socket failed: %s", strerror(errno));
		return auth_udp_sock;
	}

	if ((setsockopt(auth_udp_sock, SOL_SOCKET, SO_REUSEADDR | SO_BROADCAST, &on,
			sizeof(on))) < 0) {
		LogWrite(DRCOM, ERROR, "UDP setsockopt failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}

	if ((setsockopt(auth_udp_sock, SOL_SOCKET, SO_BINDTODEVICE, DeviceName,
			strlen(DeviceName))) < 0) {
		LogWrite(DRCOM, ERROR, "Bind UDP socket to device failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}

	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;

	serv_addr.sin_addr = udpserver_ipaddr;
	serv_addr.sin_port = htons(SERVER_PORT);

	bzero(&local_addr, sizeof(local_addr));
	local_addr.sin_family = AF_INET;

	local_addr.sin_addr = local_ipaddr;
	local_addr.sin_port = htons(SERVER_PORT);

	if (bind(auth_udp_sock, (struct sockaddr *) &(local_addr),
			sizeof(local_addr)) < 0) {
		LogWrite(DRCOM, ERROR, "Bind UDP socket to IP failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}

	return 0;
}

int auth_UDP_Sender(uint8_t *send_data, int send_data_len) {
	if (sendto(auth_udp_sock, send_data, send_data_len, 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != send_data_len) {
		//ret不等于send_data长度报错
		LogWrite(DRCOM, ERROR, "auth_UDP_Sender error: %s", strerror(errno));
		return 0;
	}
	PrintHex(DRCOM, "Packet sent", send_data, send_data_len);
	return 1;
}

int auth_UDP_Receiver(uint8_t *recv_data) {
	struct sockaddr_in clntaddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int recv_len;

	recv_len = recvfrom(auth_udp_sock, recv_data, ETH_FRAME_LEN, 0,
			(struct sockaddr*) &clntaddr, &addrlen);
	if (recv_len > 0 && memcmp(&clntaddr.sin_addr, &serv_addr.sin_addr, 4) == 0
			&& ((recv_data[0] == 0x07) || ((recv_data[0] == 0x4d) && (recv_data[1] == 0x38)))) {
		// server information is started with 0x4d38
		PrintHex(DRCOM, "Packet received", recv_data, recv_len);
		return 1;
	}
	return 0;
}

int auth_8021x_Sender(uint8_t *send_data, int send_data_len) {
	if (sendto(auth_8021x_sock, send_data, send_data_len, 0, (struct sockaddr *) &auth_8021x_addr, sizeof(auth_8021x_addr)) != send_data_len) {
		//ret不等于send_data长度报错
		LogWrite(DOT1X, ERROR, "auth_8021x_Sender error: %s", strerror(errno));
		return 0;
	}
	PrintHex(DOT1X, "Packet sent", send_data, send_data_len);
	return 1;
}

int auth_8021x_Receiver(uint8_t *recv_data) {
	struct ethhdr *recv_hdr;
	struct ethhdr *local_ethhdr;
	local_ethhdr = (struct ethhdr *) EthHeader;
	int recv_len = recv(auth_8021x_sock, recv_data, ETH_FRAME_LEN, 0);
	recv_hdr = (struct ethhdr *) recv_data;
	// 过滤掉非0x888e的报文
	if (recv_len > 0
			&& (0 == memcmp(recv_hdr->h_dest, local_ethhdr->h_source, ETH_ALEN))
			&& (htons(ETH_P_PAE) == recv_hdr->h_proto)) {
		PrintHex(DOT1X, "Packet received", recv_data, recv_len);
		return 1;
	}
	return 0;
}

size_t appendStartPkt(uint8_t header[]) {
	return AppendDrcomStartPkt(header, send_8021x_data);
}

size_t appendResponseIdentity(const uint8_t request[]) {
	return AppendDrcomResponseIdentity(request, EthHeader, UserName, send_8021x_data);
}

size_t appendResponseMD5(const uint8_t request[]) {
	return AppendDrcomResponseMD5(request, EthHeader, UserName, Password, send_8021x_data);
}

void initAuthenticationInfo() {
	memcpy(MultcastHeader, MultcastAddr, 6);
	memcpy(MultcastHeader + 6, MAC, 6);
	MultcastHeader[12] = 0x88;
	MultcastHeader[13] = 0x8e;

	memcpy(BroadcastHeader, BroadcastAddr, 6);
	memcpy(BroadcastHeader + 6, MAC, 6);
	BroadcastHeader[12] = 0x88;
	BroadcastHeader[13] = 0x8e;

	memcpy(UnicastHeader, UnicastAddr, 6);
	memcpy(UnicastHeader + 6, MAC, 6);
	UnicastHeader[12] = 0x88;
	UnicastHeader[13] = 0x8e;

	memcpy(EthHeader + 6, MAC, 6);
	EthHeader[12] = 0x88;
	EthHeader[13] = 0x8e;
}

void printIfInfo() {
	// 打印网络信息到前台显示
	LogWrite(INIT, INF, "Hostname: %s", HostName);
	LogWrite(INIT, INF, "IP: %s", inet_ntoa(local_ipaddr));
	LogWrite(INIT, INF, "DNS: %s", inet_ntoa(dns_ipaddr));
	LogWrite(INIT, INF, "UDP server: %s", inet_ntoa(udpserver_ipaddr));
	LogWrite(INIT, INF, "MAC: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}

/*
 * 发送 EAPOL Start 以获取服务器MAC地址及执行后续认证流程
 * Dr.com客户端发送EAP包目标MAC有3个：
 * 组播地址 (01:80:c2:00:00:03)
 * 广播地址 (ff:ff:ff:ff:ff:ff)
 * 锐捷交换机 (01:d0:f8:00:00:03) PS:我校应该没有这货
 */
int loginToGetServerMAC(uint8_t recv_data[]) {
	fd_set fdR;
	struct timeval timeout = { AUTH_8021X_RECV_DELAY, 0 };
	struct timeval tmp_timeout = timeout;

	send_8021x_data_len = appendStartPkt(MultcastHeader);
	auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	LogWrite(DOT1X, INF, "%s", "Client: Multcast Start.");
	times = AUTH_8021X_RECV_TIMES;
	while (resev == 0) {
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
		case -1:
			LogWrite(DOT1X, ERROR, "Select socket for first packet failed: %s",
					strerror(errno));
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_data)) {
					//已经收到了
					LogWrite(DOT1X, INF, "Received the first request.");
					resev = 1;
					times = AUTH_8021X_RECV_TIMES;
					// 初始化服务器MAC地址
					memcpy(EthHeader, recv_data + 6, 6);
					if(auth_8021x_Handler(recv_data))
						return -EPROTO; // 正常第一个请求是Identity，不会失败。
					return 0;
				} else {
					continue;
				}
			}
			break;
		}
		if (times <= 0) {
			LogWrite(DOT1X, ERROR, "Error! No Response");
			return -ENETUNREACH;
		}

		times--;

		if (send_8021x_data[1] == 0xff) {
			// 当之前广播的时候，设置为多播
			send_8021x_data_len = appendStartPkt(MultcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(DOT1X, INF, "Client: Multcast Start.");
		} else if (send_8021x_data[1] == 0x80) {
			// 当之前多播的时候，设置为广播
			send_8021x_data_len = appendStartPkt(BroadcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(DOT1X, INF, "Client: Broadcast Start.");
		}
	}
	return 0;
}

int Authentication(int client) {
	struct timeval timeout = { AUTH_8021X_RECV_DELAY, 0 };
	struct timeval tmp_timeout = timeout;
	int ret = 0;
	fd_set fdR;

	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = { 0 };
	if (auth_8021x_Init() != 0) {
		LogWrite(DOT1X, ERROR, "Unable to initialize 802.1x socket.");
		exit(EXIT_FAILURE);
	}
	initAuthenticationInfo();
	ret = auth_8021x_Logoff();
	if (client == LOGOFF) {
		close(auth_8021x_sock);
		return 0;
	}

	if (ret == 1) {
		//如果收到EAP Failure，等待2秒再发送EAPOL Start
		sleep(2);
	} else if (ret < 0) {
		goto ERR1;
	}

	if ((ret = getIfIP(auth_8021x_sock)) < 0) {
		goto ERR1;
	}
	printIfInfo();
	if ((ret = auth_UDP_Init()) != 0) {
		LogWrite(DRCOM, ERROR, "Unable to initialize UDP socket.");
		goto ERR1;
	}

	ret = loginToGetServerMAC(recv_8021x_buf);
	if(ret < 0)
		goto ERR2;

	// 计时心跳时间
	BaseHeartbeatTime = time(NULL);
	while (resev) {
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		FD_SET(auth_udp_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + auth_udp_sock + 1, &fdR, NULL, NULL,
				&tmp_timeout)) {
		case -1:
			LogWrite(ALL, ERROR, "select socket failed: %s", strerror(errno));
			ret = -1;
			resev = 0;
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_8021x_buf)) {
					if((ret = auth_8021x_Handler(recv_8021x_buf)) != 0) {
						resev = 0;
					}
				}
			}
			if (FD_ISSET(auth_udp_sock, &fdR)) {
				if (auth_UDP_Receiver(recv_udp_data)) {
					send_udp_data_len = Drcom_UDP_Handler(recv_udp_data);
					if (success_8021x && send_udp_data_len) {
						auth_UDP_Sender(send_udp_data, send_udp_data_len);
					}
				}
			}
			break;
		}
		// 如果8021x协议认证成功并且心跳时间间隔大于设定值,则发送一次心跳
		if (success_8021x && isNeedHeartBeat) {
			if ((lastHBDone == 0) && (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_TIMEOUT)) {
				// 认为已经掉线
				LogWrite(DRCOM, ERROR,	"Client: No response to last heartbeat.");
				ret = 1; //重拨
				break;
			}
			if (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_DELAY) {
				send_udp_data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter( send_udp_data, recv_udp_data);
				LogWrite(DRCOM, INF, "Client: Send alive heartbeat.");
				if (auth_UDP_Sender(send_udp_data, send_udp_data_len) == 0) {
					ret = 1; //重拨
					break;
				}
				// 发送后记下基线时间，开始重新计时心跳时间
				BaseHeartbeatTime = time(NULL);
				lastHBDone = 0;
			}
		}

	}

	success_8021x = 0;
	resev = 0;
	lastHBDone = 1;
ERR2:
	close(auth_udp_sock);
	auth_8021x_Logoff();
ERR1:
	close(auth_8021x_sock);
	return ret;
}

typedef enum {MISC_START_ALIVE=0x01, MISC_RESPONSE_FOR_ALIVE=0x02, MISC_INFO=0x03, MISC_RESPONSE_INFO=0x04, MISC_HEART_BEAT=0x0b, MISC_RESPONSE_HEART_BEAT=0x06} DRCOM_Type;
typedef enum {MISC_HEART_BEAT_01_TYPE=0x01, MISC_HEART_BEAT_02_TYPE=0x02, MISC_HEART_BEAT_03_TYPE=0x03, MISC_HEART_BEAT_04_TYPE=0x04, MISC_FILE_TYPE=0x06} DRCOM_MISC_HEART_BEAT_Type;

int Drcom_UDP_Handler(uint8_t *recv_data) {
	int data_len = 0;
	if (recv_data[0] == 0x07) {
		// 根据收到的recv_data，填充相应的send_udp_data
		switch ((DRCOM_Type) recv_data[4]) {
		case MISC_RESPONSE_FOR_ALIVE:
			// 一秒后才回复
			sleep(1);
			//ALIVE已经回复，关闭心跳计时
			isNeedHeartBeat = 0;
			BaseHeartbeatTime = time(NULL);
			lastHBDone = 1;
			data_len = Drcom_MISC_INFO_Setter(send_udp_data, recv_data);
			LogWrite(DRCOM, INF,"Server: MISC_RESPONSE_FOR_ALIVE. Send MISC_INFO.");
			break;
		case MISC_RESPONSE_INFO:
			// 存好tail信息，并顺便解密，以备后面udp报文使用
			memcpy(tailinfo, recv_data + 16, 16);
			encryptDrcomInfo(tailinfo);
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
			isNeedHeartBeat = 1;
			LogWrite(DRCOM, INF, "Server: MISC_RESPONSE_INFO. Send MISC_HEART_BEAT_01.");
			break;
		case MISC_HEART_BEAT:
			switch ((DRCOM_MISC_HEART_BEAT_Type) recv_data[5]) {
			case MISC_FILE_TYPE:
				data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
				LogWrite(DRCOM, INF, "Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
				break;
			case MISC_HEART_BEAT_02_TYPE:
				data_len = Drcom_MISC_HEART_BEAT_03_TYPE_Setter(send_udp_data, recv_data);
				LogWrite(DRCOM, INF, "Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
				break;
			case MISC_HEART_BEAT_04_TYPE:
				// 收到这个包代表完成一次心跳流程，这里要初始化时间基线，开始计时下次心跳
				BaseHeartbeatTime = time(NULL);
				lastHBDone = 1;
				LogWrite(DRCOM, INF, "Server: MISC_HEART_BEAT_04. Waiting next heart beat cycle.");
				break;
			default:
				LogWrite(DRCOM, ERROR, "Server: Unexpected heart beat request (type:0x%02hhx)!",
						recv_data[5]);
				break;
			}
			break;
		case MISC_RESPONSE_HEART_BEAT:
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
			LogWrite(DRCOM, INF, "Server: MISC_RESPONSE_HEART_BEAT. Send MISC_HEART_BEAT_01.");
			break;
		default:
			LogWrite(DRCOM, ERROR, "UDP Server: Unexpected request (type:0x%02hhx)!",
					recv_data[2]);
			break;
		}
	}

	// Message, Server information
	if ((recv_data[0] == 0x4d) && (recv_data[1] == 0x38)) {
		LogWrite(DRCOM, INF, "%s%s", "Server: Server Information: ", recv_data + 4);
	}
	memset(recv_data, 0, ETH_FRAME_LEN);
	return data_len;
}

int auth_8021x_Handler(uint8_t recv_data[]) {
	// 根据收到的Request，回复相应的Response包

	// 带eapol头的总长度
	uint16_t pkg_len = 0;
	const char *errstr;

	memcpy(&pkg_len, recv_data + 20, sizeof(pkg_len));
	pkg_len = htons(pkg_len);

	send_8021x_data_len = 0;
	if ((EAP_Code) recv_data[18] == REQUEST) {
		switch ((EAP_Type) recv_data[22]) {
		case IDENTITY:
			LogWrite(DOT1X, INF, "Server: Request Identity.");
			send_8021x_data_len = appendResponseIdentity(recv_data);
			LogWrite(DOT1X, INF, "Client: Response Identity.");
			break;
		case MD5:
			LogWrite(DOT1X, INF, "Server: Request MD5-Challenge.");
			send_8021x_data_len = appendResponseMD5(recv_data);
			LogWrite(DOT1X, INF, "Client: Response MD5-Challenge.");
			break;
		case NOTIFICATION:
			// 23是data的偏移量，pkg_len-5是减去eapol头部的data的长度
			// 在信息的最后补0，方便打印
			recv_data[23 + pkg_len - 5] = 0;
			if ((errstr = DrcomEAPErrParse((const char *) (recv_data + 23))) != NULL) {
				LogWrite(DOT1X, ERROR, "Server: Authentication failed: %s", errstr);
				return -1;
			} else {
				LogWrite(DOT1X, INF, "Server: Notification: %s", recv_data + 23);
			}
			break;
		case AVAILABLE:
			LogWrite(DOT1X, ERROR, "Unexpected request type (AVAILABLE). Pls report it.");
			break;
		case ALLOCATED_0x07:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x07). Pls report it.");
			break;
		case ALLOCATED_0x08:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x08). Pls report it.");
			break;
		default:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x%02hhx). Pls report it.",
					(EAP_Type) recv_data[22]);
			LogWrite(DOT1X, ERROR, "Exit.");
			return -1;
			break;
		}
	} else if ((EAP_Code) recv_data[18] == FAILURE) {
		// 处理认证失败信息
		success_8021x = 0;
		isNeedHeartBeat = 0;
		uint8_t errtype = recv_data[22];
		LogWrite(DOT1X, ERROR, "Server: Failure.");
		if (times > 0) {
			times--;
			sleep(AUTH_8021X_RECV_DELAY);
			/* 主动发起认证会话 */
			return 1;
		} else {
			LogWrite(DOT1X, ERROR, "Reconnection failed. Server: errtype=0x%02hhx", errtype);
			exit(EXIT_FAILURE);
		}
	} else if ((EAP_Code) recv_data[18] == SUCCESS) {
		LogWrite(DOT1X, INF, "Server: Success.");
		times = AUTH_8021X_RECV_TIMES;
		success_8021x = 1;
		send_udp_data_len = Drcom_MISC_START_ALIVE_Setter(send_udp_data,
				recv_data);
		// 一秒后才回复
		sleep(AUTH_8021X_RECV_DELAY);
		if (OnlineHookCmd) {
			system(OnlineHookCmd);
		}
		//使用心跳超时相关代码判断MISC_START_ALIVE是否超时
		isNeedHeartBeat = 1;
		BaseHeartbeatTime = time(NULL);
		lastHBDone = 0;
		auth_UDP_Sender(send_udp_data, send_udp_data_len);
	}
	// 只有大于0才发送
	if (send_8021x_data_len > 0) {
		auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	}
	return 0;
}
