/* File: auth.h
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "functions.h"
#include "young.h"
#include "info.h"
#include "drcom.h"

#define SERVER_ADDR "202.38.210.131"
#define SERVER_PORT 61440

int Authentication(int client);