#include "tracelog.h"

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
    int d,x;
    char c,*s;
    while(*fromat)
    {
        switch(*fromat)
		{
            case 's':
                s = va_arg(args, char *);
                fprintf(loging.logfile,"%s",s);
				printf("%s",s);
            break;
            case 'd':
                d = va_arg(args, int);
                fprintf(loging.logfile,"%d",d);
				printf("%d",d);
            break;
            case 'c':
                c = (char)va_arg(args, int);
                fprintf(loging.logfile,"%c",c);
				printf("%c",c);
            break;
			case 'x':
                x = (char)va_arg(args, int);
                fprintf(loging.logfile,"%02x",x);
				printf("%02x",x);
            break;
            default:
                if(*fromat!='%'&&*fromat!='\n')
				{
                    fprintf(loging.logfile,"%c",*fromat);
					printf("%c",*fromat);
				}
            break;
        }
        fromat++;
    }
    fprintf(loging.logfile,"%s","]\n");
	printf("%s","]\n");
	
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
	printf("[%s] [%s]:[",LogLevelText[loglevel-1],loging.logtime);
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