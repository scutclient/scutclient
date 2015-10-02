scutclient
=================

背景
--------

编译校园网客户端到OpenWrt中

编译方法
--------

先把源码打包成scutclient-1.5.tar.gz格式放在Openwrt编译根目录的dl文件夹
Makefile--OpenWrt重命名Makefile为放在package/scutclient中（没有该scutclient文件夹的话就自己新建一个）

运行make menuconfig后，在Network中可以找到scutclient，选择*编译

最后保存退出后，可以运行make package/scutclient/compile V=s进行编译scutclient

ipk包会出现在Openwrt编译根目录的bin文件夹中