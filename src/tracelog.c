#ifndef LOGC_H_
#define LOGC_H_
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "time.h"
#include "stdarg.h"
#include "unistd.h"
 
#define MAXLEN (2048)
#define MAXFILEPATH (512)
#define MAXFILENAME (50)
typedef enum{
    ERROR_1=-1,
    ERROR_2=-2,
    ERROR_3=-3
}ERROR0;
 
 
typedef enum{
    NONE=0,
    INF=1,
    DEBUG=2,
    ERROR=4,
    ALL=255
}LOGLEVEL;
 
typedef struct log{
    char logtime[20];
    char filepath[MAXFILEPATH];
    FILE *logfile;
}LOG;
 
typedef struct logseting{
    char filepath[MAXFILEPATH];
    unsigned int maxfilelen;
    unsigned char loglevel;
}LOGSET;
 
int LogWrite(unsigned char loglevel,char *fromat,...);
#endif /* LOGC_H_ */
#define MAXLEVELNUM (3)
 
LOGSET logsetting;
LOG loging;
 
const static char LogLevelText[4][10]={"INF","DEBUG","ERROR","ERROR"};
 
static char * getdate(char *date);
 
static unsigned char getcode(char *path){
    unsigned char code=255;
    if(strcmp("INF",path)==0)
        code=1;
    else if(strcmp("DEBUG",path)==0)
        code=2;
    else if(strcmp("ERROR",path)==0)
        code=4;
    else if(strcmp("NONE",path)==0)
        code=0;
    return code;
}
 
static unsigned char ReadConfig(char *path){
    char value[]={0x0};
    char data[50]={0x0};
 
    FILE *fpath=fopen(path,"r");
    if(fpath==NULL)
        return -1;
    fscanf(fpath,"path=%s\n",value);
    getdate(data);
    strcat(data,".log");
    strcat(value,"/");
    strcat(value,data);
    if(strcmp(value,logsetting.filepath)!=0)
        memcpy(logsetting.filepath,value,strlen(value));
    memset(value,0,sizeof(value));
 
    fscanf(fpath,"level=%s\n",value);
    logsetting.loglevel=getcode(value);
    fclose(fpath);
    return 0;
}
/*
 *日志设置信息
 * */
static LOGSET *getlogset(){
	char value[]="/tmp/scutclient_";
	char data[50]={0x0};
    getdate(data);
	strcat(data,".log");
	strcat(value,data);
	memcpy(logsetting.filepath,value,strlen(value));
    logsetting.loglevel=INF;
    logsetting.maxfilelen=1024;
	return &logsetting;
}
 
/*
 *获取日期
 * */
static char * getdate(char *date){
    time_t timer=time(NULL);
    strftime(date,11,"%Y-%m-%d",localtime(&timer));
    return date;
}
 
/*
 *获取时间
 * */
static void settime(){
    time_t timer=time(NULL);
    strftime(loging.logtime,20,"%Y-%m-%d %H:%M:%S",localtime(&timer));
}
 
/*
 *不定参打印
 * */
static void PrintfLog(char * fromat,va_list args){
    int d;
    char c,*s;
    while(*fromat)
    {
        switch(*fromat){
            case 's':{
                s = va_arg(args, char *);
                fprintf(loging.logfile,"%s",s);
                break;}
            case 'd':{
                d = va_arg(args, int);
                fprintf(loging.logfile,"%d",d);
                break;}
            case 'c':{
                c = (char)va_arg(args, int);
                fprintf(loging.logfile,"%c",c);
                break;}
            default:{
                if(*fromat!='%'&&*fromat!='\n')
                    fprintf(loging.logfile,"%c",*fromat);
                break;}
        }
        fromat++;
    }
    fprintf(loging.logfile,"%s","]\n");
}
 
static int initlog(unsigned char loglevel){
    char strdate[30]={0x0};
    LOGSET *logsetting;
    //获取日志配置信息
    if((logsetting=getlogset())==NULL){
        perror("Get Log Set Fail!");
        return -1;
    }
    if((loglevel&(logsetting->loglevel))!=loglevel)
        return -1;
 
    memset(&loging,0,sizeof(LOG));
    //获取日志时间
    settime();
    if(strlen(logsetting->filepath)==0){
        char *path=getenv("HOME");
        memcpy(logsetting->filepath,path,strlen(path));
 
        getdate(strdate);
        strcat(strdate,".log");
        strcat(logsetting->filepath,"/");
        strcat(logsetting->filepath,strdate);
    }
    memcpy(loging.filepath,logsetting->filepath,MAXFILEPATH);
    //打开日志文件
    if(loging.logfile==NULL)
        loging.logfile=fopen(loging.filepath,"a+");
    if(loging.logfile==NULL){
        perror("Open Log File Fail!");
        return -1;
    }
    //写入日志级别，日志时间
    fprintf(loging.logfile,"[%s] [%s]:[",LogLevelText[loglevel-1],loging.logtime);
    return 0;
}
 
/*
 *日志写入
 * */
int LogWrite(unsigned char loglevel,char *fromat,...){
    va_list args;
    //初始化日志
    if(initlog(loglevel)!=0)
        return -1;
    //打印日志信息
    va_start(args,fromat);
    PrintfLog(fromat,args);
    va_end(args);
    //文件刷出
    fflush(loging.logfile);
    //日志关闭
    if(loging.logfile!=NULL)
        fclose(loging.logfile);
    loging.logfile=NULL;
    return 0;
}