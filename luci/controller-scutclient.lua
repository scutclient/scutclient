module("luci.controller.scutclient", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/scutclient") then
		return
	end
		entry({"admin", "services", "scutclient"},
			alias("admin", "services", "scutclient", "settings"),
			translate("scutclient设置"),
			10
		)

		entry({"admin", "services", "scutclient", "settings"},
			cbi("scutclient/scutclient"),
			translate("设置"),
			10
		).leaf = true

		entry({"admin", "services", "scutclient", "status"},
			call("action_status"),
			translate("状态"),
			20
		).leaf = true

		entry({"admin", "services", "scutclient", "logs"},
			call("action_logs"),
			translate("日志"),
			30
		).leaf = true
end


function action_status()
	luci.template.render("scutclient/status")
	if luci.http.formvalue("redial") == "1" then
		luci.sys.call("/etc/init.d/scutclient restart")
	end
	if luci.http.formvalue("logoff") == "1" then
		luci.sys.call("/etc/init.d/scutclient logoff")
	end
end


function action_logs()
	local logfile = string.sub(
		luci.sys.exec("ls /tmp/scutclient_*.log|awk {'print $1'}|tail -n 1"),
	1, -2) or ""
	local logs = nixio.fs.readfile(logfile) or ""
	local dirname = "/tmp/scutclient-log-"..os.date("%Y%m%d-%H%M%S")
	luci.template.render("scutclient/logs", {
		logs=logs,
		dirname=dirname,
		logfile=logfile
	})

	local tar_files = {
		"/etc/config/wireless",
		"/etc/config/network",
		"/etc/config/system",
		"/etc/config/scutclient",
		"/etc/openwrt_release",
		"/etc/crontabs/root",
		"/etc/config/dhcp",
		"/tmp/dhcp.leases",
		"/etc/rc.local",
		"/tmp/scutclient.cap",
		logfile
	}

	luci.sys.call("rm /tmp/scutclient-log-*.tar")
	luci.sys.call("rm -rf /tmp/scutclient-log-*")
	luci.sys.call("rm /www/scutclient-log-*")

	local tar_dir = dirname		--为啥上下两段用的名不一样...（刚看到报错加了一行
	nixio.fs.mkdirr(tar_dir)
	--nixio.fs.mkdirr(tar_dir.."/config_files")
	table.foreach(tar_files, function(i, v)
			luci.sys.call("cp "..v.." "..tar_dir)--.."/config_files")
	end)

--[[
	下面这段打包命令输出的。。写的时候在x86上测的还以为没事。。
	841上跑了下发现严重影响性能。。
	有空再想该怎么办吧= =
	local cmds = {
		"logread", "dmesg", "ps", "wifi status", "ifstatus wan", "ifstatus lan" ,
		"route -n", "ifconfig -a", "iptables -L", "ip6tables -L" , "netstat -nlp",
		"swconfig dev switch0 show"
	}
	nixio.fs.mkdirr(tar_dir.."/cmd-outputs")
	table.foreach(cmds, function(i, v)
			luci.sys.call(v.." > "..tar_dir.."/cmd-outputs/"..string.gsub(v, " ", "_"))
	end)
--]]

	local short_dir = "./"..nixio.fs.basename(tar_dir)
	luci.sys.call("cd /tmp && tar -cvf "..short_dir..".tar "..short_dir)
	luci.sys.call("ln -sf "..tar_dir..".tar /www/"..nixio.fs.basename(tar_dir)..".tar")
end
