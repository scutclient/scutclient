scutclient
=================

# Features

* Optional [luci](https://github.com/scutclient/luci-app-scutclient) interface
* Base on raw socket
* Independent of pcap & pthread library

# Automake

```bash
autoreconf -fi
./configure
make
sudo make install
```
Configure with `--prefix="/path/to/bin"` to specify destination.

# OpenWrt

* Place "openwrt" folder in Buildroot/packages and renamed "scutclient"
* Build command
```bash
make package/scutclient/compile V=s
```

# Contact us

SCUT Router Group (Audit) on QQ : [262939451](http://jq.qq.com/?_wv=1027&k=2EzygcA)

SCUT Router Group on [Sina Weibo](http://weibo.com/u/5148048459)

# Licenses

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

![](https://www.gnu.org/graphics/agplv3-155x51.png)

We believe that you know what you are doing. You should get this software for free.
