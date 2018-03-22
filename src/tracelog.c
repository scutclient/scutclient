#include "tracelog.h"
// 默认日志最大100KB大小
#define MAXFILELEN 102400
char logtime[20];
char filepath[MAXFILEPATH] = "/tmp/scutclient.log";
FILE *logfile;
LOGLEVEL cloglev = INF;

const static char *LogLevelText[] =
		{ "NONE", "ERROR", "INF", "DEBUG", "TRACE" };
const static char *LogTypeText[] =
		{ "ALL", "INIT", "8021X", "DRCOM" };

static unsigned long get_file_size(const char *path) {
	unsigned long filesize = -1;
	struct stat statbuff;
	if (stat(path, &statbuff) < 0) {
		return filesize;
	} else {
		filesize = statbuff.st_size;
	}
	return filesize;
}

/*
 *获取时间
 * */
static void settime() {
	time_t timer = time(NULL);
	strftime(logtime, 20, "%Y-%m-%d %H:%M:%S", localtime(&timer));
}

static int initlog(LOGTYPE logtype, LOGLEVEL loglevel) {
	//获取日志时间
	settime();

	// 判定是否大于指定的大小，进行重命名为备份文件
	if (get_file_size(filepath) > MAXFILELEN) {
		char cmdbuf[256] = { 0 };
		strcat(cmdbuf, "mv ");
		strcat(cmdbuf, filepath);
		strcat(cmdbuf, " ");
		strcat(cmdbuf, filepath);
		strcat(cmdbuf, ".backup.log");
		if ((access(filepath, F_OK)) != -1) {
			system(cmdbuf);
		}
	}

	if ((logfile = fopen(filepath, "a+")) == NULL) {
		perror("Unable to open log file");
		return -1;
	}
	//写入日志级别，日志时间
	fprintf(logfile, "[%s][%-5s][%-3s]:[", logtime, LogTypeText[logtype], LogLevelText[loglevel]);
	printf("[%s][%-5s][%-3s]:[", logtime, LogTypeText[logtype], LogLevelText[loglevel]);
	return 0;
}

/*
 *日志写入
 * */
int LogWrite(LOGTYPE logtype, LOGLEVEL loglevel, char *format, ...) {
	va_list args;

	if (loglevel > cloglev)
		return 0;
	//初始化日志
	if (initlog(logtype, loglevel) != 0)
		return -1;
	//打印日志信息
	va_start(args, format);
	vfprintf(logfile, format, args);
	va_end(args);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	fprintf(logfile, "]\n");
	printf("]\n");
	//文件刷出
	fflush(logfile);
	//日志关闭
	fclose(logfile);
	return 0;
}
