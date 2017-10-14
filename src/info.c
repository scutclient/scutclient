#include "info.h"




/* \BE\B2̬\B1\E4\C1\BF*/

/* \BE\B2̬\B3\A3\C1\BF*/
const unsigned char GET_WAN_DEV[]="uci get network.wan.ifname"; // \BB\F1ȡwan\BF\DA\CE\EF\C0\ED\B6˿\DA
const unsigned char GET_WAN_MAC[]="uci get network.wan.macaddr"; // \BB\F1ȡwan\BF\DAMAC\B5\D8ַ
const unsigned char GET_WAN_IP[]="uci get network.wan.ipaddr"; // \BB\F1ȡwan\BF\DAIP\B5\D8ַ
const unsigned char GET_WAN_NETMASK[]="uci get network.wan.netmask"; // \BB\F1ȡwan\BF\DAnetmask
const unsigned char GET_WAN_GATEWAY[]="uci get network.wan.gateway"; // \BB\F1ȡwan\BF\DA\CD\F8\B9ص\D8ַ
const unsigned char GET_DNS[]="uci get network.wan.dns | cut -d ' ' -f 1"; // \BB\F1ȡDNS\B5\D8ַ
const unsigned char GET_HOST_NAME[]="uci get scutclient.@drcom[0].hostname"; // \BB\F1ȡ\D6\F7\BB\FA\C3\FB\D7\D6
const unsigned char GET_UDP_SERVER_IP[]="uci get scutclient.@drcom[0].server_auth_ip"; // \BB\F1ȡUDP\C8\CF֤\B7\FE\CE\F1\C6\F7\B5\D8ַ
const unsigned char GET_VERSION[]="uci get scutclient.@drcom[0].version"; // \BB\F1ȡ\B0汾\BA\C5
const unsigned char GET_HASH[]="uci get scutclient.@drcom[0].hash"; // \BB\F1ȡHASHֵ
const unsigned char GET_DEBUG[]="uci get scutclient.@option[0].debug"; // \BB\F1ȡ\CAǷ\F1\BF\AA\C6\F4debug\C8\D5־
const unsigned char GET_RANDOM_STR[]="cat /proc/sys/kernel/random/uuid"; // \BB\F1ȡ\CB\E6\BB\FA\D7ַ\FB\B4\AE
const unsigned char FIX_HOSTNAME_STR[]="DESKTOP-"; // \BB\F1ȡ\B9̶\A8\D6\F7\BB\FA\C3\FB\BF\AAͷ
/* \BE\B2̬\B3\A3\C1\BF*/

int trim(char s[])  
{
	int n;
	for(n = strlen(s) - 1; n >= 0; n--)
	{
		if(s[n]!=' ' && s[n]!='\t' && s[n]!='\n' && s[n]!='\r')
		{
			break;
		}
		s[n] = '\0';
	}
	return n;
}

int checkInitForChar(unsigned char *str )
{
	int i =0;
	int result = 0;
	for(i=0;i<strlen(str);i++)
	{
		result += str[i];
	}
	return result;
}

int checkInit( uint8_t info[] ,int infoLen )
{
	int i =0;
	int result = 0;
	for(i=0;i<infoLen;i++)
	{
		result += info[i];
	}
	return result;
}

void hexStrToByte(unsigned char* source,unsigned  char* dest, int sourceLen)  
{
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2)
	{
		highByte = toupper(source[i]);
		lowByte= toupper(source[i + 1]);

		if (highByte > 0x39)
		{
			highByte -= 0x37;
		}
		else
		{
			highByte -= 0x30;
		}

		if (lowByte > 0x39)
		{
			lowByte -= 0x37;
		}
		else
		{
			lowByte -= 0x30;
		}

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return ;
}

void transIP( unsigned char *str, uint8_t iphex[] )
{
	unsigned char *p;
	int count=0;
	p = strtok(str, ".");
	if(p != NULL)
	{
		iphex[count++] = atol(p);
		while(1)
		{
			p = strtok(NULL, ".");
			if(p == NULL)
			{
				break;
			}
			else
			{
				iphex[count++] = atol(p);
			}
		}
	}
}

void transMAC( unsigned char *str, uint8_t MAC[] ) 
{
	unsigned char *p;
	int count=0;
	p = strtok(str, ":");
	if(p != NULL)
	{
		MAC[count++] = strtoul(p,0,16);
		while(1)
		{
			p = strtok(NULL, ":");
			if(p == NULL)
			{
				break;
			}
			else
			{
				MAC[count++] = strtoul(p,0,16);
			}
		}
	}
}



