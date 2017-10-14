#ifndef __INFO_H__
#define __INFO_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <getopt.h>

// 命令行参数 
// args: 2-optional 1-required 0-noargs
static const struct option long_options[] = {
	// must be specificed
  {"username",  1, NULL, 'u'},
  {"password",  1, NULL, 'p'},
  {"iface", 	1, NULL, 'f'},
  {"mac",       1, NULL, 'm'},
  {"ip",        1, NULL, 'a'},
  {"dns",       1, NULL, 'n'},
  {"hostname",  1, NULL, 't'},
  {"udp-server",1, NULL, 's'},
  {"cli-version",1,NULL, 'c'},
  {"hash",      1, NULL, 'h'},

	// logoff
  {"logoff",    0, NULL, 'o'}
};


// 默认配置




void GetWanIpAddressFromDevice(unsigned char info[]);
void GetUdpServerIpAddressFromDevice(unsigned char info[]);
void GetUdpServerIpFromDevice(uint8_t info[]);
void GetWanIpFromDevice(uint8_t info[]);
void GetWanNetMaskFromDevice(uint8_t info[]);
void GetWanGatewayFromDevice(uint8_t info[]);
void GetWanDnsFromDevice(uint8_t info[]);
void GetMacFromDevice(uint8_t info[]);
void InitUserName(unsigned char *initInfo);
void GetUserName(unsigned char *info);
void InitPassword(unsigned char *initInfo);
void GetPassword(unsigned char *info);
void SetDeviceName(unsigned char *initInfo);
void InitDeviceName();
void GetDeviceName(unsigned char *info);
void GetHostNameFromDevice(unsigned char *info);
void SetRandomHostName();
void GetHashFromDevice(unsigned char *info);
void GetDebugFromDevice(unsigned char *info);
int GetVersionFromDevice(unsigned char *info);


#endif

