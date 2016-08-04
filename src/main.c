/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */
#include "auth.h"
#include "info.h"

const static int LOGOFF = 0; // 下线标志位
const static int YOUNG_CLIENT = 1; // 翼起来客户端标志位
const static int DRCOM_CLIENT = 2; // Drcom客户端标志位

void init(int argc, char *argv[], int client)
{
	if(client == LOGOFF)
	{
		InitDeviceName();
		return;
	}
	int index = 0;
	if(client != YOUNG_CLIENT)
	{
		index = 1;
	}
	if (argc == (4+index))
	{
		SetDeviceName(argv[3+index]); // 允许从命令行指定设备名
		InitUserName(argv[1+index]);
		InitPassword(argv[2+index]);	
	} 
	if (argc == (3+index) || argc == (2+index)) 
	{
		InitUserName(argv[1+index]);
		if (argc == (2+index))
		{
			InitPassword(argv[1+index]);
		}
		else 
		{
			InitPassword(argv[2+index]);
		}
		InitDeviceName();
	} 
}

int main(int argc, char *argv[])
{
	int client=0;
	printf("\n***************************************************************\n\n");
	printf("SCUTclient is based on njit8021xclient which is made by liuqun.\n");
	printf("Welcome to join in Router of SCUT QQ group 262939451.\n\n");
	printf("\n***************************************************************\n");
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		printf("Sorry,it is unroot.\n");
		exit(-1);
	}

	/* 检查命令行参数格式 */
	if (argc<2 || argc>5) {
		printf("Command is Illegal ,You can input command like this:\n");
		printf("    %s logoff\n", argv[0]);
		printf("    %s username\n", argv[0]);
		printf("    %s username password \n", argv[0]);
		printf("    %s username password Interface_Of_Wan\n", argv[0]);
		printf("    %s drcom username\n", argv[0]);
		printf("    %s drcom username password \n", argv[0]);
		printf("    %s drcom username password Interface_Of_Wan\n", argv[0]);
		exit(-1);
	} 

	if(*argv[1]!='d'|| *argv[1]!='D')
	{
		client = YOUNG_CLIENT;
	}

	if( *argv[1]=='d' || *argv[1]=='D')
	{
		client = DRCOM_CLIENT;
	}
	
	if( *argv[1]=='l' || *argv[1]=='L')
	{
		client = LOGOFF;
	}
	
	/* 初始化环境信息 */
	init(argc,argv,client);
	
	/* 调用子函数完成802.1X认证 */
	Authentication(client);

	return (0);
}

