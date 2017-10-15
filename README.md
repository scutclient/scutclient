scutclient
=================
Dev branch here. Please use the master branch.  


# To-do 
* Use getopt() to get auth informations instead of shell    
* Test on other Linux distributions  
* ...  

Now it is available on ubuntu， you can try it as follow:
```bash
git clone https://github.com/scutclient/scutclient.git -b dev
cd scutclient 
aclocal
autoconf
autoheader
automake --add-missing 
./configure
make
```

To use it,
```bash
sudo ./scutclient --username USERNAME --password PASSWORD --iface eth1 --mac 00:11:22:33:44:55 --ip 12.34.56.78 --dns 222.201.130.30 --hostname Lenovo-PC --udp-server 202.38.210.131 --cli-version 4472434f4d0096022a --hash 2ec15ad258aee9604b18f2f8114da38db16efd00
```


If any advice, open an issue or contact us at SCUT Router Group.

# Contact us

SCUT Router Group (Audit) on QQ : [262939451](http://jq.qq.com/?_wv=1027&k=2EzygcA)

SCUT Router Group on [Sina Weibo](http://weibo.com/u/5148048459)

SCUT Router Podcast on [Telegram](https://t.me/joinchat/AAAAAERy9tE0gUvyTM_GrA)

# Licenses

[AGPLv3](https://www.gnu.org/licenses/agpl-3.0.html)

![](https://www.gnu.org/graphics/agplv3-155x51.png)

We believe that you know what you are doing. You should get this software for free.
