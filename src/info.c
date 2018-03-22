#include "info.h"
#include "tracelog.h"

int trim(char s[]) {
	int n;
	for (n = strlen(s) - 1; n >= 0; n--) {
		if (s[n] != ' ' && s[n] != '\t' && s[n] != '\n' && s[n] != '\r') {
			break;
		}
		s[n] = '\0';
	}
	return n;
}

int checkInit(uint8_t info[], int infoLen) {
	int i = 0;
	int result = 0;
	for (i = 0; i < infoLen; i++) {
		result += info[i];
	}
	return result;
}

void hexStrToByte(const char* source, unsigned char* dest, int sourceLen) {
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2) {
		highByte = toupper(source[i]);
		lowByte = toupper(source[i + 1]);

		if (highByte > 0x39) {
			highByte -= 0x37;
		} else {
			highByte -= 0x30;
		}

		if (lowByte > 0x39) {
			lowByte -= 0x37;
		} else {
			lowByte -= 0x30;
		}

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return;
}

int GetMacOfDevice(const char *ifn, uint8_t *mac) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Unable to get MAC address of %s.", ifn);
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}

int GetIPOfDevice(const char *ifn, in_addr_t *pip) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		LogWrite(DRCOM, ERROR, "Unable to get IP address of %s", ifn);
		close(fd);
		return -1;
	}
	close(fd);
	*pip = (((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);
	return 0;
}
