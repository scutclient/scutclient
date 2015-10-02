/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* 子函数声明 */
int Authentication(int client);
char *UserName;
char *Password;
char *DeviceName;
int LogWrite(unsigned char loglevel,char *fromat,...);
typedef enum{
    NONE=0,
    INF=1,
    DEBUG=2,
    ERROR=4,
    ALL=255
}LOGLEVEL;
int main(int argc, char *argv[])
{
	LogWrite(INF,"%s","#Start scutclient#");
	int client=0;
	printf("\n***************************************************************\n\n");
	printf("SCUTclient is based on njit8021xclient which is made by liuqun.\n");
	printf("Welcome to join in Router of SCUT QQ group 262939451.\n\n");
	printf("\n***************************************************************\n");
	/* 检查当前是否具有root权限 */
	if (getuid() != 0) {
		LogWrite(ERROR,"%s","Sorry,it is unroot.");
		printf("Sorry,it is unroot.\n");
		exit(-1);
	}

	/* 检查命令行参数格式 */
	if (argc<2 || argc>5) {
		printf("Command is Illegal ,You can input command like this:\n");
		printf("    %s username\n", argv[0]);
		printf("    %s username password \n", argv[0]);
		printf("    %s username password Interface_Of_Wan\n", argv[0]);
		printf("    %s inode username\n", argv[0]);
		printf("    %s inode username password \n", argv[0]);
		printf("    %s inode username password Interface_Of_Wan\n", argv[0]);
		printf("    %s digital username\n", argv[0]);
		printf("    %s digital username password \n", argv[0]);
		printf("    %s digital username password Interface_Of_Wan\n", argv[0]);
		exit(-1);
	} 


	if(*argv[1]!='i' || *argv[1]!='d'||*argv[1]!='I' || *argv[1]!='D')
	{
	client = 1;
		if (argc == 4)
		{
			DeviceName = argv[3]; // 允许从命令行指定设备名
			UserName = argv[1];
			Password = argv[2];	
		} 
		if (argc == 3 || argc == 2) 
		{
			UserName = argv[1];
			if (argc == 2)
			{
				Password = UserName;// 用户名和密码相同
			}
			else 
			{
				Password = argv[2];
			}
			FILE   *stream;
			char   buf[32]={0};
			char   tmp[32]={0} ;
			int	count = 0;
			//memset( buf, '/0', sizeof(buf) );
			stream = popen( "uci get network.wan.ifname", "r" );
			if(stream == NULL)
				printf("Command error : uci get network.wan.ifname not found , this command is used on OpenWRT");
			else
			{
				count = fread( buf, sizeof(char), sizeof(buf), stream); 
				DeviceName=tmp;
				memcpy(DeviceName, buf , count-1);
			}
			pclose( stream ); 
		} 
	}
	
	if( *argv[1]=='i' || *argv[1]=='I')
	{
		client = 2;
		if (argc == 5)
		{

			DeviceName = argv[4]; // 允许从命令行指定设备名
			UserName = argv[2];
			Password = argv[3];	
		} 
		if (argc == 4 || argc == 3) 
		{
			UserName = argv[2];
			if (argc == 3)
			{
				Password = UserName;// 用户名和密码相同
			}
			else 
			{
				Password = argv[3];
			}
			FILE   *stream;
			char   buf[32]={0};
			char   tmp[32]={0} ;
			int	count = 0;
			//memset( buf, '/0', sizeof(buf) );
			stream = popen( "uci get network.wan.ifname", "r" );
			if(stream == NULL)
				printf("Command error : uci get network.wan.ifname not found , this command is used on OpenWRT\n");
			else
			{
				count = fread( buf, sizeof(char), sizeof(buf), stream); 
				DeviceName=tmp;
				memcpy(DeviceName, buf , count-1);
			}
			pclose( stream ); 
		} 
	}
	
	if( *argv[1]=='d' || *argv[1]=='D')
	{
	client = 3;
		if (argc == 5)
		{
			DeviceName = argv[4]; // 允许从命令行指定设备名
			UserName = argv[2];
			Password = argv[3];	
		} 
		if (argc == 4 || argc == 3) 
		{
			UserName = argv[2];
			if (argc == 3)
			{
				Password = UserName;// 用户名和密码相同
			}
			else 
			{
				Password = argv[3];
			}
			FILE   *stream;
			char   buf[32]={0};
			char   tmp[32]={0} ;
			int	count = 0;
			//memset( buf, '/0', sizeof(buf) );
			stream = popen( "uci get network.wan.ifname", "r" );
			if(stream == NULL)
				printf("Command error : uci get network.wan.ifname not found , this command is used on OpenWRT\n");
			else
			{
				count = fread( buf, sizeof(char), sizeof(buf), stream); 
				DeviceName=tmp;
				memcpy(DeviceName, buf , count-1);
			}
			pclose( stream ); 
		} 
	}

	/* 调用子函数完成802.1X认证 */
	Authentication(client);

	return (0);
}

