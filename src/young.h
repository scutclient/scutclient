#include "functions.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

size_t AppendYoungStartPkt( uint8_t EthHeader[], uint8_t *Packet );
size_t AppendYoungResponseIdentity(const uint8_t request[],uint8_t EthHeader[], unsigned char ipaddrinfo[], unsigned char *UserName, uint8_t *Packet);
size_t AppendYoungResponseMD5(const uint8_t request[],uint8_t EthHeader[], unsigned char ipaddrinfo[], unsigned char *UserName, unsigned char *Password, uint8_t *Packet);
size_t AppendYoungLogoffPkt(uint8_t EthHeader[], uint8_t *Packet);
void InitCheckSumForYoung();