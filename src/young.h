#include "functions.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h>

size_t SendYoungStartPkt( uint8_t EthHeader[], uint8_t *Packet );
size_t SendYoungResponseIdentity(const uint8_t request[],uint8_t EthHeader[], unsigned char ipaddrinfo[], unsigned char *UserName, uint8_t *Packet);
size_t SendYoungResponseMD5(const uint8_t request[],uint8_t EthHeader[], unsigned char ipaddrinfo[], unsigned char *UserName, unsigned char *Password, uint8_t *Packet);
size_t SendYoungLogoffPkt(uint8_t EthHeader[], uint8_t *Packet);
void InitCheckSumForYoung();