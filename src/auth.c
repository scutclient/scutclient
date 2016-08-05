/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include "auth.h"
#include "tracelog.h"
#include "info.h"
/* 静态变量*/
static uint8_t precaptured=0xff;
static uint8_t Packet[255]={0xff};
static int resev=0;
static int times=5;
static int savedump=1;
static int success_8021x=0;
static int success_udp_recv=0;
static int RESPONSE_FOR_ALIVE=0;
static int RESPONSE_INFO=0;
static int MISC_TYPE_2=0;
static int MISC_TYPE_4=0;
static uint8_t EthHeader[14] = {0};
static uint8_t BroadcastHeader[14] = {0};
static uint8_t MultcastHeader[14] = {0};
static size_t packetlen = 0;
static int clientHandler = 0;
/* 静态变量*/

/* 静态常量*/
const static uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const static uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const static int LOGOFF = 0; // 下线标志位
const static int YOUNG_CLIENT = 1; // 翼起来客户端标志位
const static int DRCOM_CLIENT = 2; // Drcom客户端标志位
/* 静态常量*/
 
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef uint8_t EAP_ID;
pcap_t *adhandle; // adapter handle
pcap_dumper_t *dumpfile; //dumpfile
// 子函数声明
void pcap_8021x_Handler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t *capture);
void appendStartPkt();
void appendResponseIdentity(const uint8_t request[]);
void appendResponseMD5(const uint8_t request[]);
void appendLogoffPkt();

/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

void appendStartPkt()
{
	 if(clientHandler == YOUNG_CLIENT)
	 {
		SendYoungStartPkt( EthHeader, Packet );
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		SendDrcomStartPkt( EthHeader, Packet );
	 }
}

void appendResponseIdentity(const uint8_t request[])
{
	 if(clientHandler == YOUNG_CLIENT)
	 {
		unsigned char ipaddress[16] = {0};
		GetWanIpAddressFromDevice(ipaddress);
		unsigned char username[32] = {0};
		GetUserName(username);
		SendYoungResponseIdentity(request, EthHeader, ipaddress, username, Packet);
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		unsigned char username[32] = {0};
		GetUserName(username);
		SendDrcomResponseIdentity(request, EthHeader, username, Packet);
	 }
}

void appendResponseMD5(const uint8_t request[])
{
	 if(clientHandler == YOUNG_CLIENT)
	 {
		unsigned char ipaddress[16] = {0};
		GetWanIpAddressFromDevice(ipaddress);
		unsigned char username[32] = {0};
		GetUserName(username);
		unsigned char password[32] = {0};
		GetPassword(password);
		SendYoungResponseMD5(request, EthHeader, ipaddress, username, password, Packet);
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		unsigned char username[32] = {0};
		GetUserName(username);
		unsigned char password[32] = {0};
		GetPassword(password);
		SendDrcomResponseMD5(request, EthHeader, username, password, Packet);
	 }
}

void sendLogoffPkt()
{
	// 连发三次，确保已经下线
	 if(clientHandler == YOUNG_CLIENT)
	 {
		packetlen = SendYoungLogoffPkt(EthHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
		packetlen = SendYoungLogoffPkt(MultcastHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
		packetlen = SendYoungLogoffPkt(BroadcastHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
	 }
	 else if (clientHandler == DRCOM_CLIENT)
	 {
		packetlen = SendDrcomLogoffPkt(EthHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
		packetlen = SendDrcomLogoffPkt(MultcastHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
		packetlen = SendDrcomLogoffPkt(BroadcastHeader, Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
	 }
}


int Drcom_UDP_Sender(int sock, struct sockaddr_in serv_addr, unsigned char *clg_data, int clg_data_len)
{
	int ret = 0;
	ret = sendto(sock, clg_data, clg_data_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));  
	//将字符串发送给server,,,ret=sendto(已建立的连接，clg包，clg包长度，flags设0不变，sockaddr结构体，前者长度)
	if (ret != 8) 
	{ 
		//ret不等于clg_data长度报错
		return 0;
	}
	return 1;
}

int Drcom_UDP_Receiver(int sock, char *recv_data, int recv_len)
{
	int ret = 0;
	ret = recvfrom(sock, recv_data, recv_len, 0, NULL, NULL);
	if(ret < 0)
	{ 
		//ret小于0代表没收到
		return 0;
	}
	return 1;
}

int set_unblock(int fd, int flags)    /* flags are file status flags to turn on */
{
    int val;
 
    if((val = fcntl(fd, F_GETFL, 0)) < 0) {
        printf("[tskIpRev] : fcntl F_GETFL error");
        return -1;
    }
    val |= flags;       /* turn on flags */
 
    if(fcntl(fd, F_SETFL, val) < 0) {
        printf("[tskIpRev] : fcntl F_SETFL error");
        return -1;
    }
    return 0;
}

void *InitHeader(uint8_t Header[],const uint8_t ServerMAC[])
{
	memcpy(Header+0, ServerMAC, 6);
	uint8_t MAC[6]= {0};
	GetMacFromDevice(MAC);
	memcpy(Header+6, MAC, 6);
	Header[12] = 0x88;
	Header[13] = 0x8e;
}

int initAuthenticationInfo()
{
	InitHeader(MultcastHeader, MultcastAddr);
	InitHeader(BroadcastHeader, BroadcastAddr);
}

int Authentication(int client)
{	
	clientHandler = client;
	initAuthenticationInfo();
	uint8_t MAC[6]= {0};
	GetMacFromDevice(MAC);
	char	errbuf[PCAP_ERRBUF_SIZE];
	char	FilterStr[100];
	struct bpf_program	fcode;
	const int DefaultTimeout=100;//设置接收超时参数，单位ms
	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良
	/* 打开适配器(网卡) */
	char	devicename[16] = {0};
	GetDeviceName(devicename);
	adhandle = pcap_open_live(devicename,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) 
	{
		LogWrite(1,"%s",errbuf);
		printf("Error:%s\n", errbuf); 
		exit(-1);
	}

	dumpfile = pcap_dump_open(adhandle,"/tmp/scutclient.cap"); 
	if(dumpfile==NULL)
	{
		LogWrite(ERROR,"%s","Can not open the dumpfile in /tmp/scutclient.cap");
		printf("Can not open the dumpfile in /tmp/scutclient.cap\n");
		exit(-1);
	}
	else{
		LogWrite(INF,"%s","The dumpfile in /tmp/scutclient.cap");
		printf("The dumpfile in /tmp/scutclient.cap\n");
	}

	/*
	 * 设置过滤器：
	 * 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	 * 进入循环体前可以重设过滤器，那时再开始接收多播信息
	 */
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
							MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);

	struct pcap_pkthdr *header;
	const uint8_t	*captured;
	
	if(client==LOGOFF)
	{
		sendLogoffPkt();
		return 0;
	}
	if(client==YOUNG_CLIENT)
	{
		LogWrite(INF,"%s","SCUTclient Mode.");
		printf("SCUTclient Mode.\n");
		InitCheckSumForYoung();
		
		while(resev ==0)
		{
			if(Packet[0] == 0xff)
			{
				packetlen = SendYoungStartPkt(MultcastHeader,Packet);
				pcap_sendpacket(adhandle, Packet, packetlen);
				LogWrite(INF,"%s","SCUTclient: MultcastHeader Start.");
				printf("SCUTclient: MultcastHeader Start.\n");
			}
			else
			{
				packetlen = SendYoungStartPkt(BroadcastHeader,Packet);
				pcap_sendpacket(adhandle, Packet, packetlen);
				LogWrite(INF,"%s","SCUTclient: BroadcastHeader Start.");
				printf("SCUTclient: BroadcastHeader Start.\n");
			}
			sleep(1);
			if(times == 0)
			{
				printf("Error! No Response\n");
				LogWrite(ERROR,"%s", "Error! No Response\n");
				// 确保下线
				sendLogoffPkt();
				exit(-1);
			}
			times--;
			if(pcap_next_ex(adhandle,&header,&captured))
			{
				//已经收到了
				resev = 1;
				times = 5;
				// 初始化服务器MAC地址
				InitHeader(EthHeader, captured+6);
				pcap_8021x_Handler((unsigned char *)dumpfile,header,captured);
			}
		}
		while(resev)
		{
			if(pcap_next_ex(adhandle,&header,&captured))
			{
				pcap_8021x_Handler((unsigned char *)dumpfile,header,captured);
			}
		}
	}

	if(client==DRCOM_CLIENT)
	{
		LogWrite(INF,"%s","Drcom Mode.");
		printf("Drcom Mode.\n");
		SendDrcomStartPkt(MultcastHeader,Packet);
		pcap_sendpacket(adhandle, Packet, packetlen);
		LogWrite(INF,"%s","Drcom: Start.");
		printf("Drcom: Start.\n");
		
		printf("DR.COM INIT SOCKET\n");
        int sock=0;//定义整形变量sock
        unsigned char send_data[SEND_DATA_SIZE];                   //定义无符号字符串send_data[1000]  长度为1000
		int send_data_len = 0;                   					//定义无符号字符串send_data实际发送长度
        char recv_data[RECV_DATA_SIZE];                            //定义无符号字符串recv_data[1000]  长度为1000
		int recv_data_len = 0;                   					//定义无符号字符串recv_data实际发送长度
        struct sockaddr_in serv_addr,local_addr;                              //定义结构体sockaddr_in        serv_addr
        
        sock = socket(AF_INET, SOCK_DGRAM, 0);                     //AF_INET决定了要用ipv4地址（32位的）与端口号（16位的）的组合，。数据报式Socket（SOCK_DGRAM）是一种无连接的Socket，对应于无连接的UDP服务应用
        if (sock < 0) {                                            //sock<0即错误
            fprintf(stderr, "[drcom]: create sock failed.\n");
            exit(EXIT_FAILURE);
        }
		// 非阻塞
        set_unblock(sock, O_NONBLOCK);
		
        serv_addr.sin_family = AF_INET;                           //这三句填写sockaddr_in结构
        serv_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);       //将服务器IP转换成一个长整数型数
        serv_addr.sin_port = htons(SERVER_PORT);                  //将端口高低位互换
        
        local_addr.sin_family = AF_INET;                           //这三句填写sockaddr_in结构
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);       //将服务器IP转换成一个长整数型数
        local_addr.sin_port = htons(SERVER_PORT);                  //将端口高低位互换
		
        bind(sock,(struct sockaddr *)&(local_addr),sizeof(struct sockaddr_in));
		
		while(resev ==0)
		{
			if(Packet[0] == 0xff)
			{
				packetlen = SendDrcomStartPkt(MultcastHeader,Packet);
				pcap_sendpacket(adhandle, Packet, packetlen);
				LogWrite(INF,"%s","DrcomClient: MultcastHeader Start.");
				printf("DrcomClient: MultcastHeader Start.\n");
			}
			else
			{
				packetlen = SendDrcomStartPkt(BroadcastHeader,Packet);
				pcap_sendpacket(adhandle, Packet, packetlen);
				LogWrite(INF,"%s","DrcomClient: BroadcastHeader Start.");
				printf("DrcomClient: BroadcastHeader Start.\n");
			}
			sleep(1);
			if(times == 0)
			{
				printf("Error! No 8021x Response\n");
				LogWrite(ERROR,"%s", "Error! No 8021x Response\n");
				// 确保下线
				sendLogoffPkt();
				exit(-1);
			}
			times--;
			if(pcap_next_ex(adhandle,&header,&captured))
			{
				//已经收到了
				resev = 1;
				times = 5;
				// 初始化服务器MAC地址
				InitHeader(EthHeader, captured+6);
				pcap_8021x_Handler((unsigned char *)dumpfile,header,captured);
			}
		}
		int tryUdpRecvTimes = 0;
		send_data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
		while(resev)
		{
			if(pcap_next_ex(adhandle,&header,&captured))
			{
				pcap_8021x_Handler((unsigned char *)dumpfile,header,captured);
			}
			if(success_8021x)
			{
				if(tryUdpRecvTimes > 5)
				{
					// 5次没收到重新发送
					tryUdpRecvTimes = 0;
				}
				if(tryUdpRecvTimes == 0)
				{
					Drcom_UDP_Sender(sock, serv_addr, send_data, send_data_len);
				}
				//等1秒再收
				sleep(1);
				success_udp_recv = Drcom_UDP_Receiver(sock, recv_data, recv_data_len);
				tryUdpRecvTimes++;
				if(success_udp_recv)
				{
					send_data_len = Drcom_UDP_Handler(send_data, recv_data);
					success_udp_recv = 0;
					tryUdpRecvTimes = 0;
				}
			}
		}
	}

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
								LogWrite(INF,"[ALIVE_LOGIN_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[4],data_len);
								printf("[ALIVE_LOGIN_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[4],data_len);
							break;
							case ALIVE_HEARTBEAT_TYPE:
								data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_data,recv_data);
								LogWrite(INF,"[ALIVE_HEARTBEAT_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[4],data_len);
								printf("[ALIVE_HEARTBEAT_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[4],data_len);
							break;
							default:
								LogWrite(ERROR,"[DRCOM_ALIVE_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[4]);
								printf("[DRCOM_ALIVE_Type] UDP_Server: Request (type:%d)!\n", recv_data[4]);
								printf("Error! Unexpected request type!Restart Login...\n");
								data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
							break;
						}
					break;
					case FILE_TYPE:
						data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[FILE_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[3],data_len);
						printf("[FILE_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[3],data_len);
					break;
					default:
						LogWrite(ERROR,"[DRCOM_ALIVE_FILE_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[3]);
						printf("[DRCOM_ALIVE_FILE_Type] UDP_Server: Request (type:%d)!\n", recv_data[3]);
						printf("Error! Unexpected request type!Restart Login...\n");
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			case MISC_3000:
				data_len = Drcom_MISC_2800_01_TYPE_Setter(send_data,recv_data);
				LogWrite(INF,"[MISC_3000] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[2],data_len);
				printf("[MISC_3000] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[2],data_len);
			break;
			case MISC_2800:
				switch ((DRCOM_MISC_2800_Type)recv_data[5])
				{
					case MISC_2800_02_TYPE:
						data_len = Drcom_MISC_2800_03_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[MISC_2800_02_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[5],data_len);
						printf("[MISC_2800_02_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[5],data_len);
					break;
					case MISC_2800_04_TYPE:
						data_len = Drcom_HEARTBEAT_TYPE_Setter(send_data,recv_data);
						LogWrite(INF,"[MISC_2800_04_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[5],data_len);
						printf("[MISC_2800_04_TYPE] UDP_Server: Request (type:%d)!Response data len=%d\n", recv_data[5],data_len);
					break;
					default:
						LogWrite(ERROR,"[DRCOM_MISC_2800_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[5]);
						printf("[DRCOM_MISC_2800_Type] UDP_Server: Request (type:%d)!\n", recv_data[5]);
						printf("Error! Unexpected request type!Restart Login...\n");
						data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
					break;
				}
			break;
			default:
				LogWrite(ERROR,"[DRCOM_Type] UDP_Server: Request (type:%d)!Error! Unexpected request type!Restart Login...", recv_data[2]);
				printf("[DRCOM_Type] UDP_Server: Request (type:%d)!\n", recv_data[2]);
				printf("Error! Unexpected request type!Restart Login...\n");
				data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);
			break;
		}
	}
	return 0;
}

void pcap_8021x_Handler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t *captured)
{
	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)captured[18] == REQUEST)
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
				LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
				printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
				appendResponseIdentity(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] Client: Response Identity.", (EAP_ID)captured[19]);
				printf("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
				break;
			case MD5:
				LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
				printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
				appendResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] Client: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] Client: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
				break;
			default:
				LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
				printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
				printf("Error! Unexpected request type\n");
				LogWrite(INF,"%s", "#scutclient Exit#");
				exit(-1);
				break;
		}
	}
	else if ((EAP_Code)captured[18] == FAILURE)
	{	// 处理认证失败信息
		savedump=1;
		success_8021x = 0;
		uint8_t errtype = captured[22];
		uint8_t msgsize = captured[23];
		uint8_t infocode[2] = {captured[28],captured[29]};
		const char *msg = (const char*) &captured[24];
		LogWrite(INF,"[%d] Server: Failure.",(EAP_ID)captured[19]);
		printf("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
		LogWrite(INF,"Failure Message : %s",msg);
		printf("Failure Message : %s\n", msg);
		if (times>0)
		{
			times--;
			sleep(1);
			/* 主动发起认证会话 */
			appendStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","Client: Restart.");
			printf("Client: Restart.\n");
			pcap_sendpacket(adhandle, Packet, packetlen);

			if(savedump)
			{
				pcap_dump(param, header, captured);
				pcap_dump_flush(dumpfile);
			}
			return ;
		}
		else
		{
			LogWrite(INF,"%s","Reconnection failed.");
			printf("Reconnection failed.\n");
			exit(-1);
		}
		LogWrite(INF,"errtype=0x%02x", errtype);
		printf("errtype=0x%02x\n", errtype);
		exit(-1);
	}
	else if ((EAP_Code)captured[18] == SUCCESS)
	{
		LogWrite(INF,"[%d] Server: Success.", captured[19]);
		printf("[%d] Server: Success.\n", captured[19]);
		times=5;
		pcap_dump(param, header, captured);
		pcap_dump_flush(dumpfile);
		savedump=0;
		success_8021x = 1;
		return;
	}
	// 发送
	pcap_sendpacket(adhandle, Packet, packetlen);

	if(savedump)
	{
		pcap_dump(param, header, captured);
		pcap_dump_flush(dumpfile);
	}
	
	return ;
}
