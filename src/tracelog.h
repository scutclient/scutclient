/* File: tracelog.h
 * ------------
 * 注：日志模块头文件
 */
#ifndef LOGC_H_
#define LOGC_H_
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h> 

#define MAXLEN (2048)
#define MAXFILEPATH (512)
#define MAXFILENAME (50)

typedef enum {
	NONE = 0, ERROR = 1, INF = 2, DEBUG = 3, TRACE = 4
} LOGLEVEL;

typedef enum {
	ALL = 0, INIT = 1, DOT1X = 2, DRCOM = 3
} LOGTYPE;

extern LOGLEVEL cloglev;
int LogWrite(LOGTYPE logtype, LOGLEVEL loglevel, char *format, ...);
#endif /* LOGC_H_ */
