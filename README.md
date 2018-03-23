scutclient
=================

SCUT Dr.com(X) client written in C.

# Compiling
## Using automake (for all distribution)
```bash
git clone https://github.com/scutclient/scutclient.git
cd scutclient
autoreconf -fi
./configure
make
```

## Using OpenWrt buildroot
### Download source code
To compile the latest stable version, you only need **openwrt** directory in the source code. Buildroot will automatically download the source.

If you want to compile the latest git HEAD, you need to clone the entire repository and checkout to the branch/version you need.

### Preparation
#### Using SDK
Download and extract the SDK you need. For example(Snapshots on ar71xx):
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

If you want to compile other version you need to edit the **openwrt/Makefile** and change variable SRCDIR (at line 12) to your source code directory. 


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

# Usage
```bash
./scutclient --username <username> --password <password> [options...]
 -f, --iface <ifname> Interface to perform authentication.
 -n, --dns <dns> DNS server address to be sent to UDP server.
 -t, --hostname <hostname>
 -s, --udp-server <server>
 -c, --cli-version <client version>
 -h, --hash <hash> DrAuthSvr.dll hash value.
 -E, --auth-exec <command> Command to be execute after EAP authentication success.
 -D, --debug
 -o, --logoff
```

If any advice, open an issue or contact us at SCUT Router Group.

# Contact us

SCUT Router Group (Audit) on QQ : [262939451](http://jq.qq.com/?_wv=1027&k=2EzygcA)

SCUT Router Group on [Sina Weibo](http://weibo.com/u/5148048459)

SCUT Router Podcast on [Telegram](https://t.me/joinchat/AAAAAERy9tE0gUvyTM_GrA)

# License

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

![](https://www.gnu.org/graphics/agplv3-155x51.png)

We believe that you know what you are doing. You should get this software for free.
