/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

int Authentication(int client);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h> 
//#include <stdbool.h>

//#include <sys/ioctl.h>
//#include <net/if.h>

// 自定义常量
uint8_t	ip[4]={0};	// ip address
uint8_t mask[4]={0};
uint8_t gateway[4]={0};
uint8_t dns[4]={0};
uint8_t	MAC[6]={0};
uint8_t Packet[255]={0xff};
int lasttime=0;
int times=5;
int savedump=1;
typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef uint8_t EAP_ID;
uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址

pcap_t *adhandle; // adapter handle
pcap_dumper_t *dumpfile; //dumpfile
// 子函数声明
int LogWrite(unsigned char loglevel,char *fromat,...);
void SendYoungStartPkt();
void SendYoungLogoffPkt();
void SendYoungResponseIdentity(const uint8_t request[]);
void SendYoungResponseMD5(const uint8_t request[]);
void SendDigitalStartPkt();
void SendDigitalLogoffPkt();
void SendDigitalResponseIdentity(const uint8_t request[]);
void SendDigitalResponseMD5(const uint8_t request[]);
void SendiNodeStartPkt();
void SendiNodeLogoffPkt();
void SendiNodeResponseIdentity(const uint8_t request[]);
void SendiNodeResponseMD5(const uint8_t request[]);
void SendiNodeResponseAllocated(const uint8_t request[]);
void LastSendResponseMD5(const uint8_t request[]);

void Pcap_YoungHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*capture);
void Pcap_iNodeHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*capture);
void Pcap_DigitalHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*capture);
void GetInfoFromDevice();
void check(unsigned char *buf);
unsigned char encode(unsigned char base);
void TransMAC( char *str );
void TransIP( char *str ,uint8_t iphex[4]);

size_t userlen,iplen,packetlen=0;

uint8_t precaptured=0xff;
extern char *UserName;
extern char *Password;
extern char *DeviceName;
typedef enum{
    NONE=0,
    INF=1,
    DEBUG=2,
    ERROR=4,
    ALL=255
}LOGLEVEL;
/**
 * 函数：Authentication()
 *
 * 使用以太网进行802.1X认证(802.1X Authentication)
 * 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
 */

int Authentication(int client)
{	
	GetInfoFromDevice();
	char	errbuf[PCAP_ERRBUF_SIZE];
	char	FilterStr[100];
	struct bpf_program	fcode;
	const int DefaultTimeout=1000;//设置接收超时参数，单位ms
	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良
	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
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


	if(client==1)
	{
	LogWrite(INF,"%s","SCUTclient Mode.");
	printf("SCUTclient Mode.\n");
	SendYoungStartPkt();
	pcap_sendpacket(adhandle, Packet, packetlen);
	LogWrite(INF,"%s","SCUTclient: Start.");
	printf("SCUTclient: Start.\n");
	pcap_loop(adhandle,0,Pcap_YoungHandler,(unsigned char *)dumpfile);
	}
	if(client==2)
	{
	LogWrite(INF,"%s","iNode Mode.");
	printf("iNode Mode.\n");
	SendiNodeStartPkt();
	pcap_sendpacket(adhandle, Packet, packetlen);
	LogWrite(INF,"%s","iNode: Start.");
	printf("iNode: Start.\n");
	pcap_loop(adhandle,0,Pcap_iNodeHandler,(unsigned char *)dumpfile);
	}
	if(client==3)
	{
	LogWrite(INF,"%s","Digital China Mode.");
	printf("Digital China Mode.\n");
	SendDigitalStartPkt();
	pcap_sendpacket(adhandle, Packet, packetlen);
	LogWrite(INF,"%s","Digital: Start.");
	printf("Digital: Start.\n");
	pcap_loop(adhandle,0,Pcap_DigitalHandler,(unsigned char *)dumpfile);
	}
	
/*

	pcap_sendpacket(adhandle, Packet, packetlen);
	const struct pcap_pkthdr *header;
	const uint8_t	*captured;
	if(client==1)
	{
		LogWrite(INF,"%s","SCUTclient Mode.");
		printf("SCUTclient Mode.\n");
		SendYoungStartPkt();
		pcap_sendpacket(adhandle, Packet, packetlen);
		LogWrite(INF,"%s","SCUTclient: Start.");
		printf("SCUTclient: Start.\n");
		while(1)
		{
			if(pcap_next_ex(adhandle,&header,&captured))
//			Pcap_YoungHandler((unsigned char *)dumpfile,header,captured);
		}
	}
	if(client==2)
	{
		LogWrite(INF,"%s","iNode Mode.");
		printf("iNode Mode.\n");
		SendiNodeStartPkt();
		pcap_sendpacket(adhandle, Packet, packetlen);
		LogWrite(INF,"%s","iNode: Start.");
		printf("iNode: Start.\n");
		while(1)
		{
			if(pcap_next_ex(adhandle,&header,&captured))
			Pcap_iNodeHandler((unsigned char *)dumpfile,header,captured);
		}
	}
	if(client==3)
	{
		LogWrite(INF,"%s","Digital China Mode.");
		printf("Digital China Mode.\n");
		SendDigitalStartPkt();
		pcap_sendpacket(adhandle, Packet, packetlen);
		LogWrite(INF,"%s","Digital: Start.");
		printf("Digital: Start.\n");
		while(1)
		{
			if(pcap_next_ex(adhandle,&header,&captured))
			Pcap_DigitalHandler((unsigned char *)dumpfile,header,captured);
		}
	}
*/	
	return 1;
}

void Pcap_YoungHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*captured)
{

	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)captured[18] == REQUEST)
	{
	if(precaptured!=captured[22])
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
			SendYoungResponseIdentity(captured);
			pcap_dump((unsigned char *)dumpfile, header, captured);	
			LogWrite(INF,"[%d] SCUTclient: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] SCUTclient: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LastSendResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] SCUTclient: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] SCUTclient: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{
				SendYoungResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] SCUTclient: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] SCUTclient: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			break;
			default:
			LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("Error! Unexpected request type\n");
			LogWrite(INF,"%s", "#scutclient Exit#");
			exit(-1);
			break;
		}
	precaptured=captured[22];
	}
	else
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);	
			LogWrite(INF,"[%d] SCUTclient: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] SCUTclient: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LogWrite(INF,"[%d] SCUTclient: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] SCUTclient: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{
				LogWrite(INF,"[%d] SCUTclient: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] SCUTclient: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
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
	}
	else if ((EAP_Code)captured[18] == FAILURE)
	{	// 处理认证失败信息
		savedump=1;
		uint8_t errtype = captured[22];
		uint8_t msgsize = captured[23];
		uint8_t infocode[2] = {captured[28],captured[29]};
		const char *msg = (const char*) &captured[24];
		LogWrite(INF,"[%d] Server: Failure.",(EAP_ID)captured[19]);
		printf("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
		LogWrite(INF,"%s",msg);
		printf("%s\n", msg);
		savedump=1;
		if (times>1)
		{
			times--;
			sleep(1);
			/* 主动发起认证会话 */
			SendYoungStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","SCUTclient: Restart.");
			printf("SCUTclient: Restart.\n");
			return ;
		}
		else
		{
			if(times==0)
			{
				LogWrite(INF,"%s","Reconnection failed.");
				printf("Reconnection failed.\n");
				exit(-1);
			}
			times--;
			sleep(3);
			/* 主动发起认证会话 */
			SendYoungStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","SCUTclient: The Last Attempt of Restart.");
			printf("SCUTclient: The Last Attempt of Restart.\n");
			return ;
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

void Pcap_iNodeHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*captured)
{

	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)captured[18] == REQUEST)
	{
	//the same packet is send
	if(precaptured!=captured[22])
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
			SendiNodeResponseIdentity(captured);
			pcap_dump((unsigned char *)dumpfile, header, captured);	
			LogWrite(INF,"[%d] iNode: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] iNode: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LastSendResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] iNode: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] iNode: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{
				SendiNodeResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] iNode: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] iNode: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			break;
			case ALLOCATED:
			LogWrite(INF,"[%d] Server: Request Allocated!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Allocated!\n", (EAP_ID)captured[19]);
			SendResponseAllocated(captured);
			LogWrite(INF,"[%d] iNode: Response Allocated.", (EAP_ID)captured[19]);
			printf("[%d] iNode: Response Allocated.\n", (EAP_ID)captured[19]);
			break;
			default:
			LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("Error! Unexpected request type\n");
			LogWrite(INF,"%s", "#iNode Exit#");
			exit(-1);
			break;
		}
	precaptured=captured[22];
	}
	else
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
			LogWrite(INF,"[%d] iNode: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] iNode: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LogWrite(INF,"[%d] iNode: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] iNode: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{
				LogWrite(INF,"[%d] iNode: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] iNode: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			break;
			case ALLOCATED:
			LogWrite(INF,"[%d] iNode: Response Allocated.", (EAP_ID)captured[19]);
			printf("[%d] iNode: Response Allocated.\n", (EAP_ID)captured[19]);
			break;
			default:
			LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("Error! Unexpected request type\n");
			LogWrite(INF,"%s", "#iNode Exit#");
			exit(-1);
			break;
		}
	}
	}
	else if ((EAP_Code)captured[18] == FAILURE)
	{	// 处理认证失败信息
		savedump=1;
		uint8_t errtype = captured[22];
		uint8_t msgsize = captured[23];

		uint8_t infocode[2] = {captured[28],captured[29]};
		const char *msg = (const char*) &captured[24];
		LogWrite(INF,"[%d] Server: Failure.",(EAP_ID)captured[19]);
		printf("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
		LogWrite(INF,"%s",msg);
		printf("%s\n", msg);
		savedump=1;
		if (times>1)
		{
			times--;
			sleep(1);
			/* 主动发起认证会话 */
			SendiNodeStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","iNode: Restart.");
			printf("iNode: Restart.\n");
			return ;
		}
		else
		{
			if(times==0)
			{
				LogWrite(INF,"%s","Reconnection failed.");
				printf("Reconnection failed.\n");
				exit(-1);
			}
			times--;
			sleep(3);
			/* 主动发起认证会话 */
			SendiNodeStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","iNode: The Last Attempt of Restart.");
			printf("iNode: The Last Attempt of Restart.\n");
			return ;
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

void Pcap_DigitalHandler(unsigned char *param, const struct pcap_pkthdr *header,const uint8_t	*captured)
{

	// 根据收到的Request，回复相应的Response包
	if ((EAP_Code)captured[18] == REQUEST)
	{
	if(precaptured!=captured[22])
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
			SendDigitalResponseIdentity(captured);
			pcap_dump((unsigned char *)dumpfile, header, captured);	
			LogWrite(INF,"[%d] Digital: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] Digital: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LastSendResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);	
				LogWrite(INF,"[%d] Digital: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] Digital: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{
				SendDigitalResponseMD5(captured);
				pcap_dump((unsigned char *)dumpfile, header, captured);
				LogWrite(INF,"[%d] Digital: Response MD5-Challenge.", (EAP_ID)captured[19]);				
				printf("[%d] Digital: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			break;
			default:
			LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("Error! Unexpected request type\n");
			LogWrite(INF,"%s", "#Digital Exit#");
			exit(-1);
			break;
		}
	precaptured=captured[22];
	}
	else
	{
		switch ((EAP_Type)captured[22])
		{
			case IDENTITY:
			LogWrite(INF,"[%d] Server: Request Identity!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);	
			LogWrite(INF,"[%d] Digital: Response Identity.", (EAP_ID)captured[19]);
			printf("[%d] Digital: Response Identity.\n", (EAP_ID)captured[19]);
			break;
			case MD5:
			LogWrite(INF,"[%d] Server: Request MD5-Challenge!", (EAP_ID)captured[19]);
			printf("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
			if(times==0)
			{
				LogWrite(INF,"[%d] Digital: The Last Attempt of MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] Digital: The Last Attempt of MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			else
			{	
				LogWrite(INF,"[%d] Digital: Response MD5-Challenge.", (EAP_ID)captured[19]);
				printf("[%d] Digital: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
			}
			break;
			default:
			LogWrite(INF,"[%d] Server: Request (type:%d)!Error! Unexpected request type!", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
			printf("Error! Unexpected request type\n");
			LogWrite(INF,"%s", "#Digital Exit#");
			exit(-1);
			break;
		}
	}
	}
	else if ((EAP_Code)captured[18] == FAILURE)
	{	// 处理认证失败信息
		savedump=1;
		uint8_t errtype = captured[22];
		uint8_t msgsize = captured[23];

		uint8_t infocode[2] = {captured[28],captured[29]};
		const char *msg = (const char*) &captured[24];
		LogWrite(INF,"[%d] Server: Failure.",(EAP_ID)captured[19]);
		printf("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
		LogWrite(INF,"%s",msg);
		printf("%s\n", msg);
		savedump=1;
		if (times>1)
		{
			times--;
			sleep(1);
			/* 主动发起认证会话 */
			SendDigitalStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","Digital: Restart.");
			printf("Digital: Restart.\n");
			return ;
		}
		else
		{
			if(times==0)
			{
				LogWrite(INF,"%s","Reconnection failed.");
				printf("Reconnection failed.\n");
				exit(-1);
			}
			times--;
			sleep(3);
			/* 主动发起认证会话 */
			SendDigitalStartPkt();
			pcap_dump((unsigned char *)dumpfile, header, captured);
			LogWrite(INF,"%s","Digital: The Last Attempt of Restart.");
			printf("Digital: The Last Attempt of Restart.\n");
			return ;
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
