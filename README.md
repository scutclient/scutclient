scutclient
=================
Dev branch here. Please use the master branch.  


# To-do 
* Add argument validation
* Test on other Linux distributions  
* ...  

# Compiling
## Using automake
```bash
git clone https://github.com/scutclient/scutclient.git -b dev_rebase
cd scutclient
autoreconf -fi
./configure
make
```

To use it,
```bash
sudo ./scutclient --username USERNAME --password PASSWORD --iface eth1 --dns 222.201.130.30 --hostname Lenovo-PC --udp-server 202.38.210.131 --cli-version 4472434f4d0096022a --hash 2ec15ad258aee9604b18f2f8114da38db16efd00
```

## Using OpenWrt SDK
1. Download and extract the SDK you need. For example:
```bash
wget http://downloads.openwrt.org/snapshots/targets/ar71xx/generic/openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64.tar.xz
tar -Jxvf openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64.tar.xz
cd openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64
```
2. Clone scutclient and put the **entire** source directory into package.
```bash
git clone https://github.com/scutclient/scutclient package/scutclient -b dev_rebase
```
3. Compile the package.
```bash
make defconfig
make package/openwrt/compile V=s
```
4. The compiled ipk will be placed under **bin** directory.

If any advice, open an issue or contact us at SCUT Router Group.

# Contact us

SCUT Router Group (Audit) on QQ : [262939451](http://jq.qq.com/?_wv=1027&k=2EzygcA)

SCUT Router Group on [Sina Weibo](http://weibo.com/u/5148048459)

SCUT Router Podcast on [Telegram](https://t.me/joinchat/AAAAAERy9tE0gUvyTM_GrA)

# License

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

![](https://www.gnu.org/graphics/agplv3-155x51.png)

We believe that you know what you are doing. You should get this software for free.
