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

## Using OpenWrt buildroot
### Download source code
To compile the latest stable version, you only need openwrt/Makefile inside scutclient source code so downloading that file is enough.

If you want to compile the latest git HEAD, you need to clone the entire repository and checkout to the branch/version you need.

### Preparation
#### Using SDK
Download and extract the SDK you need. For example:
```bash
wget http://downloads.openwrt.org/snapshots/targets/ar71xx/generic/openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64.tar.xz
tar -Jxvf openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64.tar.xz
cd openwrt-sdk-ar71xx-generic_gcc-5.5.0_musl.Linux-x86_64
```

#### Using OpenWrt source code
Nothing to do here.

### Creating your package
Create a directory called scutclient inside your package directory and copy openwrt/Makefile into it. (Of course this can be done using GUI file manager :D )
```bash
mkdir package/scutclient
cp {SOMEWHERE}/openwrt/Makefile package/scutclient
```
Then you've created a package for the latest stable version.

If you want to compile other version you need to edit the Makefile and change variable SRCDIR (at line 12) to your source code directory. For example:
```make
#
# Copyright (C) 2016-2018 SCUT Router Term
#
# This is free software, licensed under the GNU Affero General Public License v3.
# See /COPYING for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=scutclient
#If you want to compile your local source code, fill the absolute source path below.
SRCDIR:=/some/where/to/scutclient
ifneq (,$(SRCDIR))
PKG_VERSION:=$(shell cd $(SRCDIR) && git describe --tags || echo "unknown")
PKG_RELEASE:=1
PKG_UNPACK=$(CP) $(SRCDIR)/. $(PKG_BUILD_DIR)
else
PKG_VERSION:=v2.2
PKG_RELEASE:=1
```

### Compiling
#### Using SDK

Execute the following command:

```bash
make defconfig
make package/scutclient/compile V=s
```
The compiled ipk will be placed under **bin** directory.

#### Using OpenWrt source code

Select **scutclient** under **Network** tab and start building your firmware.

If any advice, open an issue or contact us at SCUT Router Group.

# Contact us

SCUT Router Group (Audit) on QQ : [262939451](http://jq.qq.com/?_wv=1027&k=2EzygcA)

SCUT Router Group on [Sina Weibo](http://weibo.com/u/5148048459)

SCUT Router Podcast on [Telegram](https://t.me/joinchat/AAAAAERy9tE0gUvyTM_GrA)

# License

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

![](https://www.gnu.org/graphics/agplv3-155x51.png)

We believe that you know what you are doing. You should get this software for free.
