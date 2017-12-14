#include <time.h>
#include <netinet/in.h>
#include <stdint.h>

size_t AppendDrcomStartPkt( uint8_t EthHeader[], uint8_t *Packet );
size_t AppendDrcomResponseIdentity(const uint8_t request[], uint8_t EthHeader[], unsigned char *UserName, uint8_t *Packet );
size_t AppendDrcomResponseMD5(const uint8_t request[],uint8_t EthHeader[], unsigned char *UserName, unsigned char *Password, uint8_t *Packet);
size_t AppendDrcomLogoffPkt(uint8_t EthHeader[], uint8_t *Packet);
int Drcom_MISC_START_ALIVE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_MISC_INFO_Setter(unsigned char *send_data, char *recv_data);
int Drcom_MISC_HEART_BEAT_01_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_MISC_HEART_BEAT_03_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(unsigned char *send_data, char *recv_data);

uint8_t tailinfo[16];
void encryptDrcomInfo(unsigned char *info);