#include "functions.h"
#include "md5.h"

void PrintDebugInfo(char *type, uint8_t info[], size_t packetlen)
{
#ifdef PRINTINFO
	printf("\n*****************Send %s info***************************\n",type);
	int m,n=0;
	for(m=0;m<=packetlen-1;m++)
	{
	n++;
	if(n==17)
	{
	printf("\n");
	n=1;
	}
	printf("%02x ",Packet[m]);
	}
	printf("\n");
#endif
}

void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
	uint8_t	msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’

	int	passlen = strlen(passwd);
	int msglen = 1 + passlen + 16;
	assert(sizeof(msgbuf) >= msglen);

	msgbuf[0] = id;
	memcpy(msgbuf+1,	 passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);

	//(void)MD5(msgbuf, msglen, digest);
	MD5Calc(msgbuf, msglen, digest);
}
