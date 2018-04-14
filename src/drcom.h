#include <time.h>
#include <endian.h>
#include <netinet/in.h>
#include <stdint.h>

extern uint8_t tailinfo[16];
extern uint8_t timeNotAllowed;

size_t AppendDrcomLogoffPkt(uint8_t *EthHeader, uint8_t *Packet);
size_t AppendDrcomResponseIdentity(const uint8_t *request, uint8_t *EthHeader,
		const char *UserName, uint8_t *Packet);
size_t AppendDrcomResponseMD5(const uint8_t *request, uint8_t *EthHeader,
		const char *UserName, const char *Password, uint8_t *Packet);
size_t AppendDrcomStartPkt(uint8_t *EthHeader, uint8_t *Packet);
const char* DrcomEAPErrParse(const char *str);
int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data);
int Drcom_MISC_HEART_BEAT_01_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data);
int Drcom_MISC_HEART_BEAT_03_TYPE_Setter(uint8_t *send_data, uint8_t *recv_data);
int Drcom_MISC_INFO_Setter(uint8_t *send_data, uint8_t *recv_data);
int Drcom_MISC_START_ALIVE_Setter(uint8_t *send_data, uint8_t *recv_data);
void encryptDrcomInfo(unsigned char *info);
