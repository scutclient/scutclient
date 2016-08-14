/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include "auth.h"
#include "tracelog.h"
#include "info.h"

#define LOGOFF  0 // 下线标志位
#define YOUNG_CLIENT  1 // 翼起来客户端标志位
#define DRCOM_CLIENT  2 // Drcom客户端标志位
#define DRCOM_UDP_HEARTBEAT_DELAY  10 // Drcom客户端心跳延时秒数，默认10秒
#define DRCOM_UDP_RECV_DELAY  2 // Drcom客户端收UDP报文延时秒数，默认2秒
#define AUTH_8021X_RECV_DELAY  1 // 客户端收8021x报文延时秒数，默认1秒
#define AUTH_8021X_RECV_TIMES  10 // 客户端收8021x报文重试次数

/* 静态常量*/
const static uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const static uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const static uint8_t UnicastAddr[6] = {0x01,0xd0,0xf8,0x00,0x00,0x03}; // 单播MAC地址
/* 静态常量*/

/* 静态变量*/
static uint8_t Packet[1024]={0};
static int resev=0;
static int times=AUTH_8021X_RECV_TIMES;
static int success_8021x=0;
static uint8_t EthHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8e};
static uint8_t BroadcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x88,0x8e};
static uint8_t MultcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0xc2,0x00,0x00,0x03,0x88,0x8e};
static uint8_t UnicastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xd0,0xf8,0x00,0x00,0x03,0x88,0x8e};
static size_t packetlen = 0;
static int clientHandler = 0;
static time_t BaseHeartbeatTime = 0;  // UDP心跳基线时间
static time_t WaitUdpRecvTime = 0;  // UDP报文等待时间
static time_t Wait8021xRecvTime = 0;  // 8021x报文等待时间
static int auth_8021x_sock = 0;
static int auth_udp_sock = 0;
/* 静态变量*/

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef uint8_t EAP_ID;

// 子函数声明
void auth_8021x_Handler(uint8_t recv_data[]);
size_t appendStartPkt(uint8_t header[]);
size_t appendResponseIdentity(const uint8_t request[]);
size_t appendResponseMD5(const uint8_t request[]);
void appendLogoffPkt();

int checkWanStatus(int sock)
{
	struct ifreq ifr;
	bzero(&ifr,sizeof(ifr));
	unsigned char devicename[16] = {0};
	GetDeviceName(devicename);
	strcpy(ifr.ifr_name,devicename);
	if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
	{
		LogWrite(ERROR,"%s","ioctl get if_flag error.");
		perror("ioctl get if_flag error");
		return 0;
	}
	if(ifr.ifr_ifru.ifru_flags & IFF_RUNNING )
	{
		LogWrite(INF,"%s","WAN had linked up.");
	}
	else
	{
		LogWrite(ERROR,"%s","WAN had linked down. Please do check it.");
		perror("WAN had linked down. Please do check it.");
		return 0;
	}
	//获取接口索引
	if(ioctl(sock,SIOCGIFINDEX,&ifr) < 0)
	{
		LogWrite(ERROR,"%s","Get WAN index error.");
		perror("Get WAN index error.");
		return 0;
	}
	bzero(&auth_8021x_addr,sizeof(auth_8021x_addr));
	auth_8021x_addr.sll_ifindex = ifr.ifr_ifindex;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol  = htons(ETH_P_PAE);
	auth_8021x_addr.sll_pkttype = PACKET_HOST | PACKET_BROADCAST  | PACKET_MULTICAST | PACKET_OTHERHOST | PACKET_OUTGOING;
	return 1;
}

int auth_UDP_Sender(struct sockaddr_in serv_addr, unsigned char *send_data, int send_data_len)
{
	if (sendto(auth_udp_sock, send_data, send_data_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_UDP_Sender error.");
		perror("auth_UDP_Sender error");
		return 0;
	}
	LogWrite(INF,"%s%d","auth_UDP_Sender packetlen = ",packetlen);
	return 1;
}

int auth_UDP_Receiver(char *recv_data, int recv_len)
{
	if(recv(auth_udp_sock, recv_data, ETH_FRAME_LEN, 0) < 0)
	{ 
		//小于0代表没收到
		return 0;
	}
	return 1;
}

int auth_8021x_Sender(unsigned char *send_data, int send_data_len)
{
	if (sendto(auth_8021x_sock, send_data, send_data_len, 0, (struct sockaddr *)&auth_8021x_addr,  sizeof(auth_8021x_addr)) != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_8021x_Sender failed.");
		perror("auth_8021x_Sender failed.");
		return 0;
	}
	LogWrite(INF,"%s%d","auth_8021x_Sender packetlen = ",packetlen);
	return 1;
}

int auth_8021x_Receiver(char *recv_data)
{
	if(recv(auth_8021x_sock, recv_data, ETH_FRAME_LEN, 0) < 0)
	{ 
		//ret小于0代表没收到
		return 0;
	}
	return 1;
}

size_t appendStartPkt(uint8_t header[])
{
	 if(clientHandler == YOUNG_CLIENT)
	 {
		return AppendYoungStartPkt( header, Packet );
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		return AppendDrcomStartPkt( header, Packet );
	 }
}

size_t appendResponseIdentity(const uint8_t request[])
{
	 if(clientHandler == YOUNG_CLIENT)
	 {
		unsigned char ipaddress[16] = {0};
		GetWanIpAddressFromDevice(ipaddress);
		unsigned char username[32] = {0};
		GetUserName(username);
		return AppendYoungResponseIdentity(request, EthHeader, ipaddress, username, Packet);
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		unsigned char username[32] = {0};
		GetUserName(username);
		return AppendDrcomResponseIdentity(request, EthHeader, username, Packet);
	 }
}

size_t appendResponseMD5(const uint8_t request[])
{
	if(clientHandler == YOUNG_CLIENT)
	{
		unsigned char ipaddress[16] = {0};
		GetWanIpAddressFromDevice(ipaddress);
		unsigned char username[32] = {0};
		GetUserName(username);
		unsigned char password[32] = {0};
		GetPassword(password);
		return AppendYoungResponseMD5(request, EthHeader, ipaddress, username, password, Packet);
	}
	else if (clientHandler == DRCOM_CLIENT)
	{
		unsigned char username[32] = {0};
		GetUserName(username);
		unsigned char password[32] = {0};
		GetPassword(password);
		return AppendDrcomResponseMD5(request, EthHeader, username, password, Packet);
	}
}

void sendLogoffPkt()
{
	LogWrite(INF,"%s","Send LOGOFF.");
	// 连发三次，确保已经下线
	if(clientHandler == YOUNG_CLIENT)
	{
		packetlen = AppendYoungLogoffPkt(EthHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
		packetlen = AppendYoungLogoffPkt(MultcastHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
		packetlen = AppendYoungLogoffPkt(BroadcastHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
	}
	else if (clientHandler == DRCOM_CLIENT)
	{
		packetlen = AppendDrcomLogoffPkt(EthHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
		packetlen = AppendDrcomLogoffPkt(MultcastHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
		packetlen = AppendDrcomLogoffPkt(BroadcastHeader, Packet);
		auth_8021x_Sender(Packet, packetlen);
	}
}

int set_unblock(int fd, int flags)
{
	int val;

	if((val = fcntl(fd, F_GETFL, 0)) < 0) 
	{
		LogWrite(ERROR,"%s", "fcntl F_GETFL error.");
		perror("fcntl F_GETFL error.");
		return EXIT_FAILURE;
	}
	val |= flags;

	if(fcntl(fd, F_SETFL, val) < 0) 
	{
		LogWrite(ERROR,"%s", "fcntl F_SETFL error");
		perror("fcntl F_SETFL error.");
		return EXIT_FAILURE;
	}
	return 0;
}

void initAuthenticationInfo()
{
	uint8_t MAC[6]= {0};
	GetMacFromDevice(MAC);
	
	memcpy(MultcastHeader, MultcastAddr, 6);
	memcpy(MultcastHeader+6, MAC, 6);
	MultcastHeader[12] = 0x88;
	MultcastHeader[13] = 0x8e;
	
	memcpy(BroadcastHeader, BroadcastAddr, 6);
	memcpy(BroadcastHeader+6, MAC, 6);
	BroadcastHeader[12] = 0x88;
	BroadcastHeader[13] = 0x8e;
	
	memcpy(UnicastHeader, UnicastAddr, 6);
	memcpy(UnicastHeader+6, MAC, 6);
	UnicastHeader[12] = 0x88;
	UnicastHeader[13] = 0x8e;
	
	memcpy(EthHeader+6, MAC, 6);
	EthHeader[12] = 0x88;
	EthHeader[13] = 0x8e;
	
	// 打印网络信息到前台显示	
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","IP :",ip[0],ip[1],ip[2],ip[3]);
	GetWanNetMaskFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Netmask :",ip[0],ip[1],ip[2],ip[3]);
	GetWanGatewayFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Gateway :",ip[0],ip[1],ip[2],ip[3]);
	GetWanDnsFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Dns :",ip[0],ip[1],ip[2],ip[3]);
	LogWrite(INF,"%s %x:%x:%x:%x:%x:%x","MAC :",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
}

void loginToGetServerMAC(uint8_t recv_data[])
{
	fd_set fdR;
	
	//先发一次
	packetlen = appendStartPkt(MultcastHeader);
	auth_8021x_Sender(Packet, packetlen);
	LogWrite(INF,"%s","Client: Multcast Start.");
	times = AUTH_8021X_RECV_TIMES;
	// 记下基线时间
	Wait8021xRecvTime = time(NULL);
	while(resev ==0)
	{
		FD_ZERO(&fdR); 
		FD_SET(auth_8021x_sock, &fdR); 
		FD_SET(auth_udp_sock, &fdR); 
		switch (select(auth_8021x_sock + auth_udp_sock, &fdR, NULL, NULL, NULL)) 
		{ 
			case -1: 
				LogWrite(ERROR,"%s","select socket failed.");
				perror("select socket failed.");
			break;
			case 0: 
			break;
			default: 
				if (FD_ISSET(auth_8021x_sock,&fdR)) 
				{ 
					if(auth_8021x_Receiver(recv_data))
					{
						// 过滤掉非0x888e的报文
						if(recv_data[12]!=0x88 && recv_data[13]!=0x8e)
						{
							continue;
						}
						//已经收到了
						LogWrite(INF,"%s","Receive the first request.");
						resev = 1;
						times = AUTH_8021X_RECV_TIMES;
						// 初始化服务器MAC地址
						memcpy(EthHeader, recv_data+6,6);
						auth_8021x_Handler(recv_data);
						// 发送
						auth_8021x_Sender(Packet, packetlen);
						return;
					}
				}
			break;
		}
		if(times <= 0)
		{
			perror("No Response!");
			LogWrite(ERROR,"%s", "Error! No Response");
			// 确保下线
			sendLogoffPkt();
			exit(EXIT_FAILURE);
		}
			perror("debug");
		// 当前时间减去基线时间大于设定值的时候再发送
		if(time(NULL) - Wait8021xRecvTime > AUTH_8021X_RECV_DELAY)
		{
		
			// 记下基线时间，重新记时
			Wait8021xRecvTime = time(NULL);
			times--;
			// 当之前广播的时候，设置为多播
			if(Packet[1] == 0xff)
			{
				packetlen = appendStartPkt(MultcastHeader);
				auth_8021x_Sender(Packet, packetlen);
				LogWrite(INF,"%s","Client: Multcast Start.");
			}
			// 当之前多播的时候，设置为单播
			else if(Packet[1] == 0x80)
			{
				packetlen = appendStartPkt(UnicastHeader);
				auth_8021x_Sender(Packet, packetlen);
				LogWrite(INF,"%s","Client: Unicast Start.");
			}
			// 当之前单播的时候，设置为广播
			else if(Packet[1] == 0xd0)
			{
				packetlen = appendStartPkt(BroadcastHeader);
				auth_8021x_Sender(Packet, packetlen);
				LogWrite(INF,"%s","Client: Broadcast Start.");
			}
		}
	}
}

int Authentication(int client)
{	
	int on = 1;
	fd_set fdR;
	clientHandler = client;
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	
	if((setsockopt(auth_8021x_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
	{  
		perror("setsockopt failed");  
		exit(EXIT_FAILURE);  
	}  
	
	//非阻塞(必须在bind前)
	if(set_unblock(auth_8021x_sock, O_NONBLOCK)<0)
	{
		LogWrite(ERROR,"%s","Set unblock failed.");
		perror("Set unblock failed!");
	}
	
	int result = checkWanStatus(auth_8021x_sock);
	if(result == 0)
	{
		LogWrite(ERROR,"%s","Client exit.");
		perror("Client Exit!");
		close(auth_8021x_sock);
		exit(EXIT_FAILURE);
	}

	initAuthenticationInfo();

	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = {0};
	if(clientHandler==LOGOFF)
	{
		sendLogoffPkt();
		return 0;
	}
	if(clientHandler==YOUNG_CLIENT)
	{
		LogWrite(INF,"%s","SCUTclient Mode.");
		
		InitCheckSumForYoung();
		
		loginToGetServerMAC(recv_8021x_buf);

		while(resev)
		{
			FD_ZERO(&fdR); 
			FD_SET(auth_8021x_sock, &fdR); 
			FD_SET(auth_udp_sock, &fdR); 
			switch (select(auth_8021x_sock + auth_udp_sock, &fdR, NULL, NULL, NULL)) 
			{ 
				case -1: 
					LogWrite(ERROR,"%s","select socket failed.");
					perror("select socket failed.");
				break;
				case 0: 
				break;
				default: 
					if (FD_ISSET(auth_8021x_sock,&fdR)) 
					{ 
						if(auth_8021x_Receiver(recv_8021x_buf))
						{
							// 过滤掉非0x888e的报文
							if(recv_8021x_buf[12]==0x88 && recv_8021x_buf[13]==0x8e)
							{
								auth_8021x_Handler(recv_8021x_buf);
								// 发送
								auth_8021x_Sender(Packet, packetlen);
							}
						}
					}
				break;
			}
		}
	}

	if(clientHandler==DRCOM_CLIENT)
	{
		LogWrite(INF,"%s","Drcom Mode.");

		unsigned char send_data[ETH_FRAME_LEN] = {0};
		int send_data_len = 0;
		char recv_data[ETH_FRAME_LEN] = {0};
		int recv_data_len = 0;
		struct sockaddr_in serv_addr,local_addr;
		
		//静态全局变量auth_udp_sock
		auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (auth_udp_sock < 0) 
		{
			//auth_udp_sock<0即错误
			LogWrite(ERROR,"%s","Create auth_udp_sock failed.");
			perror("Create auth_udp_sock failed.");
			exit(EXIT_FAILURE);
		}
		// 非阻塞
		if(set_unblock(auth_udp_sock, O_NONBLOCK)<0)
		{
			LogWrite(ERROR,"%s","set unblock failed.");
			perror("set unblock failed.");
		}
		
		bzero(&serv_addr,sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		unsigned char server_ip[16]= {0};
		GetUdpServerIpAddressFromDevice(server_ip);
		serv_addr.sin_addr.s_addr = inet_addr(server_ip);
		serv_addr.sin_port = htons(SERVER_PORT);

		bzero(&local_addr,sizeof(local_addr));
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port = htons(SERVER_PORT);
		
		if((setsockopt(auth_udp_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
		{  
			perror("setsockopt failed");  
			exit(EXIT_FAILURE);  
		}  
		
		bind(auth_udp_sock,(struct sockaddr *)&(local_addr),sizeof(struct sockaddr_in));
		
		loginToGetServerMAC(recv_8021x_buf);
		
		int isHasSend = 0;
		send_data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
		while(resev)
		{
			FD_ZERO(&fdR); 
			FD_SET(auth_8021x_sock, &fdR); 
			FD_SET(auth_udp_sock, &fdR);
			switch (select(auth_8021x_sock + auth_udp_sock, &fdR, NULL, NULL, NULL)) 
			{ 
				case -1: 
					LogWrite(ERROR,"%s","select socket failed.");
					perror("select socket failed.");
				break;
				case 0:
				break;
				default: 
					if (FD_ISSET(auth_8021x_sock,&fdR)) 
					{ 
						if(auth_8021x_Receiver(recv_8021x_buf))
						{
							// 过滤掉非0x888e的报文
							if(recv_8021x_buf[12]==0x88 && recv_8021x_buf[13]==0x8e)
							{
								auth_8021x_Handler(recv_8021x_buf);
								// 发送
								auth_8021x_Sender(Packet, packetlen);
							}
						}
					} 
					else if (FD_ISSET(auth_udp_sock,&fdR)) 
					{
						if(auth_UDP_Receiver(recv_data, recv_data_len))
						{
							// 过滤掉非drcom的报文
							if(recv_data[0]!=0x07)
							{
								continue;
							}
							send_data_len = Drcom_UDP_Handler(send_data, recv_data);
							auth_UDP_Sender(serv_addr, send_data, send_data_len);
							// 收取后记下心跳的基线时间，开始记时
							BaseHeartbeatTime = time(NULL);
							isHasSend = 0;
						} 
					}
	
			}
			// 如果8021x协议认证成功并且心跳时间间隔大于设定值,则发送一次心跳
			if(success_8021x && (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_DELAY))
			{
				if(isHasSend == 0)
				{
					send_data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					auth_UDP_Sender(serv_addr, send_data, send_data_len);
					// 发送后记下基线时间，开始记时
					WaitUdpRecvTime = time(NULL);
					isHasSend = 1;
				}
				// 当前时间减去基线时间大于设定值的时候再自加
				if(time(NULL) - WaitUdpRecvTime > DRCOM_UDP_RECV_DELAY)
				{
					// 设定的DRCOM_UDP_RECV_DELAY时间到，需要发送
					isHasSend = 0;
				}
			}		
		}
		close(auth_udp_sock);
	}
	sendLogoffPkt(auth_8021x_sock);
	close(auth_8021x_sock);
	return 1;
}

typedef enum {MISC_0800=0x08, ALIVE_FILE=0x10, MISC_3000=0x30, MISC_2800=0x28} DRCOM_Type;
typedef enum {ALIVE_TYPE=0x00, FILE_TYPE=0x01} DRCOM_ALIVE_FILE_Type;
typedef enum {ALIVE_LOGIN_TYPE=0x02, ALIVE_HEARTBEAT_TYPE=0x06} DRCOM_ALIVE_Type;
typedef enum {MISC_2800_01_TYPE=0x01, MISC_2800_02_TYPE=0x02, MISC_2800_03_TYPE=0x03, MISC_2800_04_TYPE=0x04} DRCOM_MISC_2800_Type;
int Drcom_UDP_Handler(unsigned char *send_data, char *recv_data)
{
	int data_len = 0;
	// 根据收到的recv_data，填充相应的send_data
	if (recv_data[0] == 0x07)
	{
		switch ((DRCOM_Type)recv_data[2])
		{
			case ALIVE_FILE:
				switch ((DRCOM_ALIVE_FILE_Type)recv_data[3])
				{
					case ALIVE_TYPE:
						switch ((DRCOM_ALIVE_Type)recv_data[4])
						{
							case ALIVE_LOGIN_TYPE:
								data_len = Drcom_ALIVE_LOGIN_TYPE_Setter(send_data,recv_data);
								LogWrite(INF,"%s%d%s%d","[ALIVE_LOGIN_TYPE] UDP_Server: Request (type:",recv_data[4],")!Response ALIVE_LOGIN_TYPE data len=",data_len);
							break;
							case ALIVE_HEARTBEAT_TYPE:
								data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
								LogWrite(INF,"%s%d%s%d","[ALIVE_HEARTBEAT_TYPE] UDP_Server: Request (type:",recv_data[4],")!Response MISC_2800_01_TYPE data len=",data_len);
							break;
							default:
								LogWrite(ERROR,"%s%d%s","[DRCOM_ALIVE_Type] UDP_Server: Request (type:", recv_data[4],")!Error! Unexpected request type!Restart Login...");
								data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
							break;
						}
					break;
					case FILE_TYPE:
						data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"%s%d%s%d","[FILE_TYPE] UDP_Server: Request (type:",recv_data[3],")!Response MISC_2800_01_TYPE data len=",data_len);
					break;
					default:
						LogWrite(ERROR,"%s%d%s","[DRCOM_ALIVE_FILE_Type] UDP_Server: Request (type:", recv_data[3],")!Error! Unexpected request type!Restart Login...");
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			case MISC_3000:
				data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
				LogWrite(INF,"%s%d%s%d","[MISC_3000] UDP_Server: Request (type:",recv_data[2],")!Response MISC_2800_01_TYPE data len=",data_len);
			break;
			case MISC_2800:
				switch ((DRCOM_MISC_2800_Type)recv_data[5])
				{
					case MISC_2800_02_TYPE:
						data_len = Drcom_MISC_2800_03_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"%s%d%s%d","[MISC_2800_02_TYPE] UDP_Server: Request (type:",recv_data[5],")!Response MISC_2800_03_TYPE data len=",data_len);
					break;
					case MISC_2800_04_TYPE: 
					// 收到这个包代表完成一次心跳流程，这里要初始化时间基线，开始计时下次心跳
						BaseHeartbeatTime = time(NULL);
						data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"%s%d%s%d","[MISC_2800_04_TYPE] UDP_Server: Request (type:",recv_data[5],")!Response ALIVE_HEARTBEAT_TYPE data len=",data_len);
					break;
					default:
						LogWrite(ERROR,"%s%d%s","[DRCOM_MISC_2800_Type] UDP_Server: Request (type:", recv_data[5],")!Error! Unexpected request type!Restart Login...");
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			default:
				LogWrite(ERROR,"%s%d%s","[DRCOM_Type] UDP_Server: Request (type:", recv_data[2],")!Error! Unexpected request type!Restart Login...");
				data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
			break;
		}
	}
	return data_len;
}

void auth_8021x_Handler(uint8_t recv_data[])
{
	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)recv_data[18] == REQUEST)
	{
		switch ((EAP_Type)recv_data[22])
		{
			case IDENTITY:
				LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Server: Request Identity!");
				packetlen = appendResponseIdentity(recv_data);
				LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Client: Response Identity.");
				break;
			case MD5:
				LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Server: Request MD5-Challenge!");
				packetlen = appendResponseMD5(recv_data);
				LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Client: Response MD5-Challenge.");
				break;
			default:
				LogWrite(INF,"[%d] %s%d%s",(EAP_ID)recv_data[19],"Server: Request (type:",(EAP_Type)recv_data[22],")!Error! Unexpected request type!");
				LogWrite(INF,"%s", "#scutclient Exit#");
				exit(EXIT_FAILURE);
				break;
		}
	}
	else if ((EAP_Code)recv_data[18] == FAILURE)
	{	
		// 处理认证失败信息
		success_8021x = 0;
		uint8_t errtype = recv_data[22];
		uint8_t msgsize = recv_data[23];
		uint8_t infocode[2] = {recv_data[28],recv_data[29]};
		LogWrite(ERROR,"[%d] %s",(EAP_ID)recv_data[19],"Server: Failure.");
		if (times>0)
		{
			times--;
			sleep(1);
			/* 主动发起认证会话 */
			packetlen = appendStartPkt(EthHeader);
			LogWrite(INF,"%s","Client: Restart.");
			auth_8021x_Sender(Packet, packetlen);
			return ;
		}
		else
		{
			LogWrite(INF,"%s","Reconnection failed.");
			exit(EXIT_FAILURE);
		}
		LogWrite(INF,"%s%x","errtype=0x", errtype);
		exit(EXIT_FAILURE);
	}
	else if ((EAP_Code)recv_data[18] == SUCCESS)
	{
		LogWrite(INF,"[%d] %s", recv_data[19],"Server: Success.");
		times=AUTH_8021X_RECV_TIMES;
		success_8021x = 1;
		return;
	}
	return ;
}
