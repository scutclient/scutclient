#include <ctype.h>
#include "functions.h"
#include "md5.h"
static char hexret[50];
static char strret[20];

char* GenHexStr(uint8_t *content, size_t len) {
	uint8_t curcnt;
	hexret[0] = 0;
	for (curcnt = 0; (curcnt < len) && (curcnt < 8); curcnt++)
		sprintf(hexret + (curcnt * 3), "%02hhx ", content[curcnt]);
	hexret[24] = ' ';
	hexret[25] = 0; // In case len = 8
	for (; (curcnt < len) && (curcnt < 16); curcnt++)
		sprintf(hexret + (curcnt * 3) + 1, "%02hhx ", content[curcnt]);
	return hexret;
}

char* GenChrStr(uint8_t *content, size_t len) {
	uint8_t curcnt;
	strret[0] = 0;
	for (curcnt = 0; (curcnt < len) && (curcnt < 16); curcnt++)
		strret[curcnt] = (isprint(content[curcnt]) ? content[curcnt] : '.');
	strret[curcnt] = 0;
	return strret;
}

void PrintHex(LOGTYPE logt, char *descr, uint8_t *content, size_t len) {
	size_t cptr;
	if (cloglev < DEBUG)
		return;
	LogWrite(logt, DEBUG, "%s: Packet length: %lu bytes.", descr, len);
	if (cloglev < TRACE)
		return;
	LogWrite(logt, TRACE, "******************************************************************************");
	for (cptr = 0; cptr < len; cptr += 16) {
		LogWrite(logt, TRACE, "%08x %-49s  |%-16s|", cptr,
				GenHexStr(content + cptr, len - cptr),
				GenChrStr(content + cptr, len - cptr));
	}
	LogWrite(logt, TRACE, "******************************************************************************");
}

void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[],
		const uint8_t srcMD5[]) {
	uint8_t msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
	md5_state_t md5_msg;
	md5_init(&md5_msg);

	int passlen = strlen(passwd);
	int msglen = 1 + passlen + 16;

	msgbuf[0] = id;
	memcpy(msgbuf + 1, passwd, passlen);
	memcpy(msgbuf + 1 + passlen, srcMD5, 16);

	md5_append(&md5_msg, msgbuf, msglen);
	md5_finish(&md5_msg, digest);
}
