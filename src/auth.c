#include "auth.h"
#include "tracelog.h"
#include "info.h"

#define LOGOFF  0 // 下线标志位
#define DRCOM_CLIENT  1 // Drcom客户端标志位

#define DRCOM_UDP_HEARTBEAT_DELAY  12 // Drcom客户端心跳延时秒数，默认12秒
#define DRCOM_UDP_RECV_DELAY  2 // Drcom客户端收UDP报文延时秒数，默认2秒
#define AUTH_8021X_RECV_DELAY  1 // 客户端收8021x报文延时秒数，默认1秒
#define AUTH_8021X_RECV_TIMES  3 // 客户端收8021x报文重试次数

/* 静态常量*/
const static uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const static uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const static uint8_t UnicastAddr[6] = {0x01,0xd0,0xf8,0x00,0x00,0x03}; // 单播MAC地址
/* 静态常量*/

/* 静态变量*/
static uint8_t send_8021x_data[1024]={0}; // 用于存放发送8021x报文的变量
static size_t send_8021x_data_len = 0; // 用于存放发送8021x报文的变量的长度
static unsigned char send_udp_data[ETH_FRAME_LEN] = {0};
static char recv_udp_data[ETH_FRAME_LEN] = {0};
static int send_udp_data_len = 0; // 用于存放发送udp报文的变量的长度
static int resev=0; // 是否收到了第一帧报文的标志位，第一帧报文用于拿到服务器的mac
static int times=AUTH_8021X_RECV_TIMES; // 8021x断链重试次数
static int success_8021x=0; // 8021x成功登录标志位
static int isNeedHeartBeat=0;  // 是否需要发送UDP心跳
static uint8_t EthHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8e};
static uint8_t BroadcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x88,0x8e};
static uint8_t MultcastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x80,0xc2,0x00,0x00,0x03,0x88,0x8e};
static uint8_t UnicastHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xd0,0xf8,0x00,0x00,0x03,0x88,0x8e};
static int clientHandler = 0; // 判定不同客户端处理的标志位
static time_t BaseHeartbeatTime = 0;  // UDP心跳基线时间
static int auth_8021x_sock = 0; // 8021x的socket描述符
static int auth_udp_sock = 0; // udp的socket描述符
/* 静态变量*/

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED_0x07=7, ALLOCATED_0x08=8} EAP_Type;
typedef uint8_t EAP_ID;
struct sockaddr_in serv_addr,local_addr;
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
	auth_8021x_addr.sll_pkttype = PACKET_HOST;
	return 1;
}

int auth_UDP_Sender(unsigned char *send_data, int send_data_len)
{
	if (sendto(auth_udp_sock, send_data, send_data_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_UDP_Sender error.");
		perror("auth_UDP_Sender error");
		return 0;
	}
	return 1;
}

int auth_UDP_Receiver(char *recv_data)
{
	struct sockaddr_in clntaddr;
	int recv_len, addrlen = sizeof(struct sockaddr_in);
	recv_len = recvfrom(auth_udp_sock, recv_data, ETH_FRAME_LEN, 0,(struct sockaddr*) &clntaddr, &addrlen);
	if(recv_len > 0 
	&& memcmp(&clntaddr.sin_addr, &serv_addr.sin_addr, 4) == 0
	&& recv_data[0]==0x07)
	{
		return 1;
	}
	return 0;
}

int auth_8021x_Sender(unsigned char *send_data,int send_data_len)
{
	if (sendto(auth_8021x_sock, send_data, send_data_len, 0, (struct sockaddr *)&auth_8021x_addr,  sizeof(auth_8021x_addr)) != send_data_len) 
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
	struct ethhdr *recv_hdr;
	struct ethhdr *local_ethhdr;
	local_ethhdr = (struct ethhdr *) EthHeader;
	int recv_len = recv(auth_8021x_sock, recv_data, ETH_FRAME_LEN, 0);
	recv_hdr = (struct ethhdr *) recv_data;
	// 过滤掉非0x888e的报文
	if (recv_len > 0 
	&& (0 == memcmp(recv_hdr->h_dest, local_ethhdr->h_source, ETH_ALEN))
	&& (htons(ETH_P_PAE) ==  recv_hdr->h_proto) )
	{
		return 1;
	}
	return 0;
}

size_t appendStartPkt(uint8_t header[])
{
	return AppendDrcomStartPkt( header, send_8021x_data );
}

size_t appendResponseIdentity(const uint8_t request[])
{
	unsigned char username[32] = {0};
	GetUserName(username);
	return AppendDrcomResponseIdentity(request, EthHeader, username, send_8021x_data);
}

size_t appendResponseMD5(const uint8_t request[])
{
	unsigned char username[32] = {0};
	GetUserName(username);
	unsigned char password[32] = {0};
	GetPassword(password);
	return AppendDrcomResponseMD5(request, EthHeader, username, password, send_8021x_data);
}

void sendLogoffPkt()
{
	LogWrite(INF,"%s","Send LOGOFF.");
	// 连发两次，确保已经下线
	send_8021x_data_len = AppendDrcomLogoffPkt(MultcastHeader, send_8021x_data);
	auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	send_8021x_data_len = AppendDrcomLogoffPkt(MultcastHeader, send_8021x_data);
	auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
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
	struct ethhdr *recv_hdr;
	struct ethhdr *local_ethhdr;
	local_ethhdr = (struct ethhdr *) EthHeader;
	struct timeval timeout={AUTH_8021X_RECV_DELAY,0};
	struct timeval tmp_timeout=timeout;
	//先发一次
	send_8021x_data_len = appendStartPkt(MultcastHeader);
	auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	LogWrite(INF,"%s","Client: Multcast Start.");
	times = AUTH_8021X_RECV_TIMES;
	while(resev ==0)
	{
		FD_ZERO(&fdR); 
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout=timeout;
		switch (select(auth_8021x_sock+1, &fdR, NULL, NULL, &tmp_timeout)) 
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
						//已经收到了
						LogWrite(INF,"%s","Receive the first request.");
						resev = 1;
						times = AUTH_8021X_RECV_TIMES;
						// 初始化服务器MAC地址
						memcpy(EthHeader, recv_data+6,6);
						auth_8021x_Handler(recv_data);
						return;
					}
					else
					{
						continue;
					}
				}
			break;
		}
		if(times <= 0)
		{
			LogWrite(ERROR,"%s", "Error! No Response");
			// 确保下线
			sendLogoffPkt();
			exit(EXIT_FAILURE);
		}
		
		times--;

		// 当之前广播的时候，设置为多播
		if(send_8021x_data[1] == 0xff)
		{
			send_8021x_data_len = appendStartPkt(MultcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(INF,"%s","Client: Multcast Start.");
		}
		// 当之前多播的时候，设置为广播
		else if(send_8021x_data[1] == 0x80)
		{
			send_8021x_data_len = appendStartPkt(BroadcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(INF,"%s","Client: Broadcast Start.");
		}
	}
}

int Authentication(int client)
{	
	struct timeval timeout={AUTH_8021X_RECV_DELAY,0};
	struct timeval tmp_timeout=timeout;
	int on = 1;
	fd_set fdR;
	clientHandler = client;

	// 只接受EAP的包
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	
	if((setsockopt(auth_8021x_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
	{  
		perror("setsockopt failed");  
		exit(EXIT_FAILURE);  
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
	//发logoff确保下线
	sendLogoffPkt();
	
	// 计时AUTH_8021X_RECV_TIMES秒，收到Fail后退出
	BaseHeartbeatTime = time(NULL);
	while(time(NULL) - BaseHeartbeatTime < AUTH_8021X_RECV_TIMES)
	{
		FD_ZERO(&fdR); 
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) 
		{ 
			case -1: 
				LogWrite(ERROR,"%s","first select socket failed.");
				perror("first select socket failed.");
			break;
			case 0:
				LogWrite(INF,"%s","first socket select time out.");
			break;
			default: 
				if (FD_ISSET(auth_8021x_sock,&fdR)) 
				{
					if(auth_8021x_Receiver(recv_8021x_buf))
					{
						if ((EAP_Code)recv_8021x_buf[18] == FAILURE)
						{
							LogWrite(INF,"%s","Ready!Drcom Mode Go.");
							// 退出循环
							BaseHeartbeatTime = 0;
						}
					}
				}
			break;
		}
	}
	//静态全局变量auth_udp_sock
	auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (auth_udp_sock < 0) 
	{
		//auth_udp_sock<0即错误
		LogWrite(ERROR,"%s","Create auth_udp_sock failed.");
		perror("Create auth_udp_sock failed.");
		exit(EXIT_FAILURE);
	}

	bzero(&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	unsigned char server_ip[16]= {0};
	GetUdpServerIpAddressFromDevice(server_ip);
	serv_addr.sin_addr.s_addr = inet_addr(server_ip);
	serv_addr.sin_port = htons(SERVER_PORT);

	bzero(&local_addr,sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	unsigned char ip[16]= {0};
	GetWanIpAddressFromDevice(ip);
	local_addr.sin_addr.s_addr = inet_addr(ip);
	local_addr.sin_port = htons(SERVER_PORT);

	bind(auth_udp_sock,(struct sockaddr *)&(local_addr),sizeof(local_addr));
	
	loginToGetServerMAC(recv_8021x_buf);
	// 计时心跳时间
	BaseHeartbeatTime = time(NULL);
	while(resev)
	{
		FD_ZERO(&fdR); 
		FD_SET(auth_8021x_sock, &fdR); 
		FD_SET(auth_udp_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + auth_udp_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) 
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
						auth_8021x_Handler(recv_8021x_buf);
					}
				} 
				if (FD_ISSET(auth_udp_sock,&fdR)) 
				{
					if(auth_UDP_Receiver(recv_udp_data))
					{
						send_udp_data_len = Drcom_UDP_Handler(recv_udp_data);
						if(success_8021x && send_udp_data_len)
						{
							auth_UDP_Sender(send_udp_data, send_udp_data_len);
						}
					} 
				}
			break;
		}
		// 如果8021x协议认证成功并且心跳时间间隔大于设定值,则发送一次心跳
		if(success_8021x && isNeedHeartBeat && (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_DELAY))
		{
			send_udp_data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_udp_data,recv_udp_data);
			LogWrite(INF,"%s%d"," UDP_Client: Send ALIVE_HEARTBEAT, data len = ",send_udp_data_len);
			auth_UDP_Sender(send_udp_data, send_udp_data_len);
			// 发送后记下基线时间，开始重新计时心跳时间
			BaseHeartbeatTime = time(NULL);
		}	
		
	}
	close(auth_udp_sock);
	
	sendLogoffPkt(auth_8021x_sock);
	close(auth_8021x_sock);
	return 1;
}

typedef enum {MISC_START_ALIVE=0x01, MISC_RESPONSE_FOR_ALIVE=0x02, MISC_INFO=0x03, MISC_RESPONSE_INFO=0x04, MISC_HEART_BEAT=0x0b, MISC_RESPONSE_HEART_BEAT=0x06} DRCOM_Type;
typedef enum {MISC_HEART_BEAT_01_TYPE=0x01, MISC_HEART_BEAT_02_TYPE=0x02, MISC_HEART_BEAT_03_TYPE=0x03, MISC_HEART_BEAT_04_TYPE=0x04, MISC_FILE_TYPE=0x06} DRCOM_MISC_HEART_BEAT_Type;
int Drcom_UDP_Handler(char *recv_data)
{
	int data_len = 0;
	// 根据收到的recv_data，填充相应的send_udp_data
	switch ((DRCOM_Type)recv_data[4])
	{
		case MISC_RESPONSE_FOR_ALIVE:
			// 一秒后才回复
			sleep(1);
			data_len = Drcom_MISC_INFO_Setter(send_udp_data,recv_data);
			LogWrite(INF,"%s%x%s%d"," UDP_Server: MISC_RESPONSE_FOR_ALIVE (step:0x",recv_data[4],")!Send MISC_INFO, data len = ",data_len);
		break;
		case MISC_RESPONSE_INFO:
			// 存好tail信息，并顺便解密，以备后面udp报文使用
			memcpy(tailinfo,recv_data+16,16);
			encrypt(tailinfo);
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data,recv_data);
			isNeedHeartBeat = 1;
			LogWrite(INF,"%s%x%s%d"," UDP_Server: MISC_RESPONSE_INFO (step:0x",recv_data[4],")!Send MISC_HEART_BEAT_01, data len = ",data_len);
		break;
		case MISC_HEART_BEAT:
			switch ((DRCOM_MISC_HEART_BEAT_Type)recv_data[5])
			{
				case MISC_FILE_TYPE:
					data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data,recv_data);
					LogWrite(INF,"%s%x%s%d"," UDP_Server: MISC_FILE_TYPE (type:0x",recv_data[5],")!Send MISC_HEART_BEAT_01, data len = ",data_len);
				break;
				case MISC_HEART_BEAT_02_TYPE:
					data_len = Drcom_MISC_HEART_BEAT_03_TYPE_Setter(send_udp_data,recv_data);
					LogWrite(INF,"%s%x%s%d"," UDP_Server: Request MISC_HEART_BEAT_02 (type:0x",recv_data[5],")!Response MISC_HEART_BEAT_03_TYPE data len=",data_len);
				break;
				case MISC_HEART_BEAT_04_TYPE: 
				// 收到这个包代表完成一次心跳流程，这里要初始化时间基线，开始计时下次心跳
					BaseHeartbeatTime = time(NULL);
					LogWrite(INF,"%s%x%s%d"," UDP_Server: Request HEART_BEAT_04 (type:0x",recv_data[5],")!Response ALIVE_HEARTBEAT_TYPE data len=",data_len);
				break;
				default:
					LogWrite(ERROR,"%s%x%s","[DRCOM_MISC_HEART_BEAT_Type] UDP_Server: Request (type:0x", recv_data[5],")!Error! Unexpected request type!");
				break;
			}
		break;
		case MISC_RESPONSE_HEART_BEAT:
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data,recv_data);
			LogWrite(INF,"%s%x%s%d"," UDP_Server: MISC_RESPONSE_HEART_BEAT (step:0x",recv_data[4],")!Send MISC_HEART_BEAT_01, data len = ",data_len);
		break;
		default:
			LogWrite(ERROR,"%s%x%s","[DRCOM_Type] UDP_Server: Request (type:0x", recv_data[2],")!Error! Unexpected request type!");
		break;
	}
	return data_len;
}

void auth_8021x_Handler(uint8_t recv_data[])
{
	// 根据收到的Request，回复相应的Response包
	send_8021x_data_len = 0;
	if ((EAP_Code)recv_data[18] == REQUEST)
	{
		switch ((EAP_Type)recv_data[22])
		{
			case IDENTITY:
				LogWrite(INF,"%s", "Server: Request Identity!");
				send_8021x_data_len = appendResponseIdentity(recv_data);
				LogWrite(INF,"%s%d", "Client: Response Identity. send_8021x_data_len = ", send_8021x_data_len);
			break;
			case MD5:
				LogWrite(INF,"%s", "Server: Request MD5-Challenge!");
				send_8021x_data_len = appendResponseMD5(recv_data);
				LogWrite(INF,"%s%d", "Client: Response MD5-Challenge. send_8021x_data_len = ", send_8021x_data_len);
			break;
			case NOTIFICATION:
				LogWrite(ERROR,"%s","Error! Unexpected request type!Server: Request NOTIFICATION !Pls report it.");
			break;
			case AVAILABLE:
				LogWrite(ERROR,"%s","Error! Unexpected request type!Server: Request AVAILABLE !Pls report it.");
			break;
			case ALLOCATED_0x07:
				LogWrite(ERROR,"%s","Error! Unexpected request type!Server: Request ALLOCATED_0x07 !Pls report it.");
			break;
			case ALLOCATED_0x08:
				LogWrite(ERROR,"%s","Error! Unexpected request type!Server: Request ALLOCATED_0x08 !Pls report it.");
			break;
			default:
				LogWrite(ERROR,"%s%x%s","Server: Request (type:0x",(EAP_Type)recv_data[22],")!Error! Unexpected request type!Pls report it.");
				LogWrite(ERROR,"%s", "#scutclient Exit#");
				exit(EXIT_FAILURE);
			break;
		}
	}
	else if ((EAP_Code)recv_data[18] == FAILURE)
	{	
		// 处理认证失败信息
		success_8021x = 0;
		isNeedHeartBeat = 0;
		uint8_t errtype = recv_data[22];
		LogWrite(ERROR,"%s","Server: Failure.");
		// TODO:暂时不自动重拨
		//times = 0;
		if (times>0)
		{
			times--;
			sleep(AUTH_8021X_RECV_DELAY);
			/* 主动发起认证会话 */
			send_8021x_data_len = appendStartPkt(EthHeader);
			LogWrite(ERROR,"%s%x","Server: errtype = 0x", errtype);
			LogWrite(INF,"%s","Client: Multcast Restart.");
		}
		else
		{
			LogWrite(ERROR,"%s%x","Reconnection failed.Server: errtype=0x", errtype);
			exit(EXIT_FAILURE);
		}
	}
	else if ((EAP_Code)recv_data[18] == SUCCESS)
	{
		LogWrite(INF,"%s", "Server: Success.");
		times=AUTH_8021X_RECV_TIMES;
		success_8021x = 1;
		send_udp_data_len = Drcom_MISC_START_ALIVE_Setter(send_udp_data,recv_data);
		// 一秒后才回复
		sleep(AUTH_8021X_RECV_DELAY);
		auth_UDP_Sender(send_udp_data, send_udp_data_len);
	}
	// 只有大于0才发送
	if(send_8021x_data_len > 0)
	{
		auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	}
	return ;
}
