/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include "auth.h"
#include "tracelog.h"
#include "info.h"
/* 静态变量*/
static uint8_t Packet[1024]={0};
static int resev=0;
static int times=15;
static int success_8021x=0;
static int success_udp_recv=0;
static uint8_t EthHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8e};
static uint8_t BroadcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x88,0x8e};
static uint8_t MultcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0xc2,0x00,0x00,0x03,0x88,0x8e};
static uint8_t UnicastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xd0,0xf8,0x00,0x00,0x03,0x88,0x8e};
static size_t packetlen = 0;
static int clientHandler = 0;
static time_t BaseHeartbeatTime = 0;  // UDP心跳基线时间
static time_t WaitRecvTime = 0;  // UDP报文等待时间
static int auth_8021x_sock = 0;
static int auth_udp_sock = 0;
/* 静态变量*/

/* 静态常量*/
const static uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const static uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const static uint8_t UnicastAddr[6] = {0x01,0xd0,0xf8,0x00,0x00,0x03}; // 单播MAC地址
const static int LOGOFF = 0; // 下线标志位
const static int YOUNG_CLIENT = 1; // 翼起来客户端标志位
const static int DRCOM_CLIENT = 2; // Drcom客户端标志位
const static int DRCOM_UDP_HEARTBEAT_DELAY = 600; // Drcom客户端心跳延时秒数，默认600秒
const static int DRCOM_UDP_RECV_DELAY = 2; // Drcom客户端收UDP报文延时秒数，默认2秒
/* 静态常量*/
 
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
	int	err = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if( err < 0)
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
	if(-1 == ioctl(sock,SIOCGIFINDEX,&ifr))
	{
		LogWrite(ERROR,"%s","Get WAN index error.");
		perror("Get WAN index error.");
		return 0;
	}
	auth_8021x_addr.sll_ifindex = ifr.ifr_ifindex;
	auth_8021x_addr.sll_family = PF_PACKET;
	
	return 1;
}

int auth_UDP_Sender(struct sockaddr_in serv_addr, unsigned char *send_data, int send_data_len)
{
	int ret = 0;
	ret = sendto(auth_udp_sock, send_data, send_data_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (ret != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_UDP_Sender error.");
		perror("auth_UDP_Sender error");
		return 0;
	}
	return 1;
}

int auth_UDP_Receiver(char *recv_data, int recv_len)
{
	int ret = 0;
	ret = recvfrom(auth_udp_sock, recv_data, recv_len, 0, NULL, NULL);
	if(ret < 0)
	{ 
		//ret小于0代表没收到
		return 0;
	}
	return 1;
}

int auth_8021x_Sender(unsigned char *send_data, int send_data_len)
{
	int ret = 0;
	ret = send(auth_8021x_sock, send_data, send_data_len, 0);
	if (ret != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_8021x_Sender failed.");
		perror("auth_8021x_Sender failed.");
		return 0;
	}
	return 1;
}

int auth_8021x_Receiver(char *recv_data)
{
	int ret = 0;
	int recv_len = 0;
	ret = recv(auth_8021x_sock, recv_data, recv_len, 0);
	if(ret < 0)
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
		return -1;
	}
	val |= flags;

	if(fcntl(fd, F_SETFL, val) < 0) 
	{
		LogWrite(ERROR,"%s", "fcntl F_SETFL error");
		perror("fcntl F_SETFL error.");
		return -1;
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
	uint8_t info[4]= {0};
	GetWanIpFromDevice(info);
	LogWrite(INF,"%s","IP : %d.%d.%d.%d",info[0],info[1],info[2],info[3]);
	GetWanNetMaskFromDevice(info);
	LogWrite(INF,"%s","Netmask : %d.%d.%d.%d",info[0],info[1],info[2],info[3]);
	GetWanGatewayFromDevice(info);
	LogWrite(INF,"%s","Gateway : %d.%d.%d.%d",info[0],info[1],info[2],info[3]);
	GetWanDnsFromDevice(info);
	LogWrite(INF,"%s","Dns : %d.%d.%d.%d",info[0],info[1],info[2],info[3]);
	LogWrite(INF,"%s","MAC : %02x:%02x:%02x:%02x:%02x:%02x",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
}

void loginToGetServerMAC(uint8_t recv_data[])
{
	packetlen = appendStartPkt(MultcastHeader);
	while(resev ==0)
	{
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
		sleep(2);
		if(times == 0)
		{
			perror("No Response!");
			LogWrite(ERROR,"%s", "Error! No Response");
			// 确保下线
			sendLogoffPkt();
			exit(-1);
		}
		times--;
		if(auth_8021x_Receiver(recv_data))
		{
			//已经收到了
			LogWrite(INF,"%s","Receive the first request.");
			resev = 1;
			times = 15;
			// 初始化服务器MAC地址
			memcpy(EthHeader, recv_data+6,6);
			auth_8021x_Handler(recv_data);
		}
	}
}

int Authentication(int client)
{	
	clientHandler = client;
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	
	// 非阻塞(必须在bind前)
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
	// 绑定sock，只接收指定端口发来的报文
	if (bind(auth_8021x_sock, (struct sockaddr*)&auth_8021x_addr, sizeof(struct sockaddr_ll)) < 0)
	{
		LogWrite(ERROR,"%s","Bind WAN interface failed.");
		perror("Error!");
		return 0;
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
			if(auth_8021x_Receiver(recv_8021x_buf))
			{
				auth_8021x_Handler(recv_8021x_buf);
			}
		}
	}

	if(clientHandler==DRCOM_CLIENT)
	{
		LogWrite(INF,"%s","Drcom Mode.");

		unsigned char send_data[ETH_FRAME_LEN];
		int send_data_len = 0;
		char recv_data[ETH_FRAME_LEN];
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
		// 非阻塞(必须在bind前)
		if(set_unblock(auth_udp_sock, O_NONBLOCK)<0)
		{
			LogWrite(ERROR,"%s","set unblock failed.\n");
			perror("set unblock failed.\n");
		}
		// 检测网口是否连上，并设置混杂模式
		if(!checkWanStatus(auth_udp_sock))
		{
			LogWrite(ERROR,"%s","Client exit.");
			perror("Client exit.");
			close(auth_8021x_sock);
			exit(EXIT_FAILURE);
		}
		serv_addr.sin_family = AF_INET;
		unsigned char server_ip[16]= {0};
		GetUdpServerIpAddressFromDevice(server_ip);
		serv_addr.sin_addr.s_addr = inet_addr(server_ip);
		serv_addr.sin_port = htons(SERVER_PORT);

		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port = htons(SERVER_PORT);
		
		bind(auth_udp_sock,(struct sockaddr *)&(local_addr),sizeof(struct sockaddr_in));
		
		loginToGetServerMAC(recv_8021x_buf);
		
		int tryUdpRecvTimes = 0;
		send_data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
		while(resev)
		{
			if(auth_8021x_Receiver(recv_8021x_buf))
			{
				auth_8021x_Handler(recv_8021x_buf);
			}
			// 如果8021x协议认证成功并且心跳时间间隔大于设定值
			if(success_8021x && (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_DELAY))
			{
				if(tryUdpRecvTimes > 5)
				{
					// 5次没收到重新发送
					tryUdpRecvTimes = 0;
				}
				if(tryUdpRecvTimes == 0)
				{
					auth_UDP_Sender(serv_addr, send_data, send_data_len);
					// 发送后记下基线时间，开始记时
					WaitRecvTime = time(NULL);
				}
				// 尝试收报文
				success_udp_recv = auth_UDP_Receiver(recv_data, recv_data_len);
				// 当前时间减去基线时间大于设定值的时候再自加
				if(time(NULL) - WaitRecvTime > DRCOM_UDP_RECV_DELAY)
				{
					// 记下基线时间，重新记时
					WaitRecvTime = time(NULL);
					tryUdpRecvTimes++;
				}
				if(success_udp_recv)
				{
					send_data_len = Drcom_UDP_Handler(send_data, recv_data);
					success_udp_recv = 0;
					tryUdpRecvTimes = 0;
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
								LogWrite(INF,"[ALIVE_LOGIN_TYPE] UDP_Server: Request (type:%d)!Response ALIVE_LOGIN_TYPE data len=%d", recv_data[4],data_len);
							break;
							case ALIVE_HEARTBEAT_TYPE:
								data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
								LogWrite(INF,"[ALIVE_HEARTBEAT_TYPE] UDP_Server: Request (type:%d)!Response MISC_2800_01_TYPE data len=%d", recv_data[4],data_len);
							break;
							default:
								LogWrite(ERROR,"[DRCOM_ALIVE_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[4]);
								data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
							break;
						}
					break;
					case FILE_TYPE:
						data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[FILE_TYPE] UDP_Server: Request (type:%d)!Response MISC_2800_01_TYPE data len=%d", recv_data[3],data_len);
					break;
					default:
						LogWrite(ERROR,"[DRCOM_ALIVE_FILE_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[3]);
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			case MISC_3000:
				data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
				LogWrite(INF,"[MISC_3000] UDP_Server: Request (type:%d)!Response MISC_2800_01_TYPE data len=%d", recv_data[2],data_len);
			break;
			case MISC_2800:
				switch ((DRCOM_MISC_2800_Type)recv_data[5])
				{
					case MISC_2800_02_TYPE:
						data_len = Drcom_MISC_2800_03_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[MISC_2800_02_TYPE] UDP_Server: Request (type:%d)!Response MISC_2800_03_TYPE data len=%d", recv_data[5],data_len);
					break;
					case MISC_2800_04_TYPE: 
					// 收到这个包代表完成一次心跳流程，这里要初始化时间基线，开始计时下次心跳
						BaseHeartbeatTime = time(NULL);
						data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[MISC_2800_04_TYPE] UDP_Server: Request (type:%d)!Response ALIVE_HEARTBEAT_TYPE data len=%d", recv_data[5],data_len);
					break;
					default:
						LogWrite(ERROR,"[DRCOM_MISC_2800_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[5]);
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			default:
				LogWrite(ERROR,"[DRCOM_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[2]);
				data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
			break;
		}
	}
	return 0;
}

void auth_8021x_Handler(uint8_t recv_data[])
{
	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)recv_data[18] == REQUEST)
	{
		switch ((EAP_Type)recv_data[22])
		{
			case IDENTITY:
				LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)recv_data[19]);
				packetlen = appendResponseIdentity(recv_data);
				LogWrite(INF,"[%d] Client: Response Identity.", (EAP_ID)recv_data[19]);
				break;
			case MD5:
				LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)recv_data[19]);
				packetlen = appendResponseMD5(recv_data);
				LogWrite(INF,"[%d] Client: Response MD5-Challenge.", (EAP_ID)recv_data[19]);
				break;
			default:
				LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)recv_data[19], (EAP_Type)recv_data[22]);
				LogWrite(INF,"%s", "#scutclient Exit#");
				exit(-1);
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
		const char *msg = (const char*) &recv_data[24];
		LogWrite(ERROR,"[%d] Server: Failure.",(EAP_ID)recv_data[19]);
		LogWrite(ERROR,"Failure Message : %s",msg);
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
			exit(-1);
		}
		LogWrite(INF,"errtype=0x%02x", errtype);
		exit(-1);
	}
	else if ((EAP_Code)recv_data[18] == SUCCESS)
	{
		LogWrite(INF,"[%d] Server: Success.", recv_data[19]);
		times=15;
		success_8021x = 1;
		return;
	}
	// 发送
	auth_8021x_Sender(Packet, packetlen);
	return ;
}
