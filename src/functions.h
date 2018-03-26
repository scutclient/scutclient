#include <stdint.h>
#include "tracelog.h"

void PrintHex(LOGTYPE logt, char *descr, uint8_t *content, size_t len);
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[],
		const uint8_t srcMD5[]);
