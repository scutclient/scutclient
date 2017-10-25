#include "info.h"

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

int GetMacOfDevice(const char *ifn, uint8_t *mac)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&ifr,sizeof(ifr));
	strncpy(ifr.ifr_name,ifn, IFNAMSIZ-1);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		fprintf(stderr, "Unable to get MAC address of %s\n", ifn);
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(mac, ifr.ifr_hwaddr.sa_data,6);
	return 0;
}

int GetIPOfDevice(const char *ifn, uint32_t *pip)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifn, IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFADDR, &ifr) < 0)
	{
		fprintf(stderr, "Unable to get IP address of %s\n", ifn);
		close(fd);
		return -1;
	}
	close(fd);
	*pip = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
	return 0;
}
