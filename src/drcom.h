#include <time.h>
#include <netinet/in.h>
#include <stdint.h>


size_t AppendDrcomStartPkt( uint8_t EthHeader[], uint8_t *Packet );
size_t AppendDrcomResponseIdentity(const uint8_t request[], uint8_t EthHeader[], unsigned char *UserName, uint8_t *Packet );
size_t AppendDrcomResponseMD5(const uint8_t request[],uint8_t EthHeader[], unsigned char *UserName, unsigned char *Password, uint8_t *Packet);
size_t AppendDrcomLogoffPkt(uint8_t EthHeader[], uint8_t *Packet);
int Drcom_LOGIN_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_ALIVE_LOGIN_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_MISC_2800_01_TYPE_Setter(unsigned char *send_data, char *recv_data);
int Drcom_MISC_2800_03_TYPE_Setter(unsigned char *send_data, char *recv_data);