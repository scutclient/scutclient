scutclient
=================

# 特性

* 可选[luci](https://github.com/scutclient/luci-app-scutclient)界面
* 采用socket raw，减少libpcap等等的第三方库的依赖
* 单线程

# 编译方法

* openwrt目录重命名scutclient为放在Openwrt Buildroot的package文件夹中
* 运行
```shell
make menuconfig
```
在Network中可以找到scutclient，选择*/M编译，然后保存退出
* 确保执行make后没有报错，能正常编译固件后，执行
```shell
make package/scutclient/compile V=s
```
编译scutclient
* ipk包会出现在Openwrt编译根目录的bin文件夹中

# 许可证

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

特别指出禁止任何个人或组织将 [scutclient](http://github.com/scutclient/) 的代码投入商业使用，由此造成的后果和法律责任均与本项目无关。 
