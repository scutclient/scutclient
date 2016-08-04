#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//#define PRINTINFO 1

void PrintDebugInfo(char *type, uint8_t info[], size_t packetlen);
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[]);
