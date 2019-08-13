#ifndef __INFO_H__
#define __INFO_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <getopt.h>

extern struct in_addr udpserver_ipaddr;
extern struct in_addr dns_ipaddr;
extern char *UserName;
extern char *Password;
extern char *OnlineHookCmd;
extern char *OfflineHookCmd;
extern char DeviceName[IFNAMSIZ];
extern char HostName[32];
extern char *Hash;
extern unsigned char Version[64];
extern int Version_len;

int hexStrToByte(const char* source, unsigned char* dest, int bufLen);
#endif

