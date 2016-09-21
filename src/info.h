#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>

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

