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

// 命令行参数 
// args: 2-optional 1-required 0-noargs
static const struct option long_options[] = {
	// must be specificed
  {"username",  1, NULL, 'u'},
  {"password",  1, NULL, 'p'},
  {"iface",     1, NULL, 'f'},
  {"dns",       1, NULL, 'n'},
  {"hostname",  1, NULL, 't'},
  {"udp-server",1, NULL, 's'},
  {"cli-version",1,NULL, 'c'},
  {"hash",      1, NULL, 'h'},
  {"debug",     0, NULL, 'D'},
	// logoff
  {"logoff",    0, NULL, 'o'},
  {NULL,        0, NULL, 0}
};


// 默认配置

void hexStrToByte(unsigned char* source,unsigned  char* dest, int sourceLen);
void transIP( unsigned char *str, uint8_t iphex[] );
void transMAC( unsigned char *str, uint8_t MAC[] );
int GetMacOfDevice(const char *ifn, uint8_t *mac);
int GetIPOfDevice(const char *ifn, uint32_t *pip);
#endif

