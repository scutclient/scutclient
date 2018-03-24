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
static const struct option long_options[] = {
	{"username", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'p'},
	{"iface", required_argument, NULL, 'f'},
	{"dns", required_argument, NULL, 'n'},
	{"hostname", required_argument, NULL, 't'},
	{"udp-server", required_argument, NULL, 's'},
	{"cli-version", required_argument,NULL, 'c'},
	{"hash", required_argument, NULL, 'h'},
	{"auth-exec", required_argument, NULL, 'E'},
	{"debug", optional_argument, NULL, 'D'},
	{"logoff", no_argument, NULL, 'o'},
	{NULL, no_argument, NULL, 0}
};

void hexStrToByte(const char* source, unsigned char* dest, int sourceLen);
#endif

