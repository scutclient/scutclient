scutclient
=================

# 特性

* 自带luci界面
* 采用socket raw，减少libpcap等等的第三方库的依赖
* 单线程

# 编译方法

* 先把源码打包成scutclient-1.6.tar.gz格式放在Openwrt编译根目录的dl文件夹
* Makefile--OpenWrt重命名Makefile为放在package/scutclient中（没有该scutclient文件夹的话就自己新建一个）
* 运行make menuconfig后，在Network中可以找到scutclient，选择*编译，然后保存退出
* 确保执行make后没有报错，能正常编译固件后，才可以执行make package/scutclient/compile V=s进行编译scutclient
* ipk包会出现在Openwrt编译根目录的bin文件夹中

# 许可证

AGPLv3

特别指出禁止任何个人或者公司将 [scutclient](http://github.com/scutclient/) 的代码投入商业使用，由此造成的后果和法律责任均与本人无关。 
