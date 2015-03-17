本程序采用静态编译，集成libpcap
解压后，进入编译根目录
tar.gz源码包放在dl文件夹，Makefile放在package/scutclient中
（没有该scutclient文件夹的话就自己新建一个）

该版本是适用于AR71XX处理器系列的源代码，如果需要编译其他版本的处理器，
请把源码包中的libpcap.a替换成你需要编译的版本即可。

libpcap.a的生成方法：
1.在编译选项界面，先选择libpcap,然后运行make,编译一次，如果之前编译过
scutclient旧版本（1.4以下），那么就不用这一步
2.编译后，可以在
根目录/build_dir/对应的编译处理器/libpcap-X.X/libpcap.a
里面找到

最后，可以运行make package/scutclient/compile V=s对scutclient进行编译，
编译完之后可以在/bin/对应的处理器/packages中找到
