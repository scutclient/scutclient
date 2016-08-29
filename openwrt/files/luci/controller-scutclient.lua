module("luci.controller.scutclient", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/scutclient") then
		return
	end
		entry({"admin", "scutclient"},
			alias("admin", "scutclient", "settings"),
			translate("华南理工大学客户端"),
			10
		)

		entry({"admin", "scutclient", "settings"},
			cbi("scutclient/scutclient"),
			translate("设置"),
			10
		).leaf = true

		entry({"admin", "scutclient", "status"},
			call("action_status"),
			translate("状态"),
			20
		).leaf = true

		entry({"admin", "scutclient", "logs"},
			call("action_logs"),
			translate("日志"),
			30
		).leaf = true
end


function action_status()
	luci.template.render("scutclient/status")
	if luci.http.formvalue("logoff") == "1" then
		luci.sys.call("/etc/init.d/scutclient stop > /dev/null")
	end
end


function action_logs()
	luci.sys.call("touch /tmp/scutclient.log")
	luci.sys.call("touch /tmp/scutclient.log.backup.log")
	local logfile = string.sub(luci.sys.exec("ls /tmp/scutclient.log"),1, -2) or ""
	local backuplogfile = string.sub(luci.sys.exec("ls /tmp/scutclient.log.backup.log"),1, -2) or ""
	local logs = nixio.fs.readfile(logfile) or ""
	local backuplogs = nixio.fs.readfile(backuplogfile) or ""
	local dirname = "/tmp/scutclient-log-"..os.date("%Y%m%d-%H%M%S")
	luci.template.render("scutclient/logs", {
		logs=logs,
		backuplogs=backuplogs,
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
		logfile,
		backuplogfile
	}

	luci.sys.call("rm /tmp/scutclient-log-*.tar")
	luci.sys.call("rm -rf /tmp/scutclient-log-*")
	luci.sys.call("rm /www/scutclient-log-*")

	local tar_dir = dirname		
	nixio.fs.mkdirr(tar_dir)
	table.foreach(tar_files, function(i, v)
			luci.sys.call("cp "..v.." "..tar_dir)
	end)


	local short_dir = "./"..nixio.fs.basename(tar_dir)
	luci.sys.call("cd /tmp && tar -cvf "..short_dir..".tar "..short_dir)
	luci.sys.call("ln -sf "..tar_dir..".tar /www/"..nixio.fs.basename(tar_dir)..".tar")
end
