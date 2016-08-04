/* File: auth.h
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h> 
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "functions.h"
#include "young.h"
#include "info.h"
#include "drcom.h"

#define SERVER_ADDR "202.38.210.131"
#define SERVER_PORT 61440

#define RECV_DATA_SIZE 1000
#define SEND_DATA_SIZE 1000
#define CHALLENGE_TRY 10
#define LOGIN_TRY 5
#define ALIVE_TRY 5

/* infomation */
struct user_info_pkt {
    char *username;
    char *password;
    char *hostname;
    char *os_name;
    uint64_t mac_addr;                 //unsigned long int
    int username_len;
    int password_len;
    int hostname_len;
    int os_name_len;
};


int Authentication(int client);