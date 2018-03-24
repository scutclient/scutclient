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

