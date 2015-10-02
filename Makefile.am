AUTOMAKE_OPTIONS=foreign   #只检测必要文件
bin_PROGRAMS=scutclient #指定所要产生的可执行文件的文件名
#指定产生“scutclient”时所需要的源代码和头文件
scutclient_SOURCES=\
		src/main.c \
		src/auth.c \
		src/functions.c \
		src/young.c \
		src/inode.c \	
		src/digital.c \
		src/tracelog.c \
		$(NULL)
scutclient_LDADD=-lpcap


