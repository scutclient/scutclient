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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "functions.h"
#include "info.h"
#include "drcom.h"

#define LOGOFF 0 // 下线标志位
#define SERVER_ADDR "202.38.210.131"
#define SERVER_PORT 61440
#define DNS_ADDR "222.201.130.30"

size_t appendResponseIdentity(const uint8_t request[]);
size_t appendResponseMD5(const uint8_t request[]);
size_t appendStartPkt(uint8_t header[]);
int auth_8021x_Handler(uint8_t recv_data[]);
int auth_8021x_Init();
int auth_8021x_Logoff();
int auth_8021x_Receiver(uint8_t *recv_data);
int auth_8021x_Sender(uint8_t *send_data, int send_data_len);
int auth_UDP_Init();
int auth_UDP_Receiver(uint8_t *recv_data);
int auth_UDP_Sender(uint8_t *send_data, int send_data_len);
int Authentication(int client);
int Drcom_UDP_Handler(uint8_t *recv_data);
void initAuthenticationInfo();
int loginToGetServerMAC(uint8_t recv_data[]);
void printIfInfo();

