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


void hexStrToByte(const char* source, unsigned char* dest, int sourceLen);
#endif

