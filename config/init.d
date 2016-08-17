#!/bin/sh /etc/rc.common	
	
START=99	
STOP=15	
	
	
auth() {	
	
	if [ $(uci get scutclient.@option[0].enable) -eq 0 ]	
	then	
		exit	
	fi	
		
	rm /tmp/scutclient_*.log	

	scutclient drcom \
	$(uci get scutclient.@scutclient[0].username) \	
	$(uci get scutclient.@scutclient[0].password) \		
	$(uci get scutclient.@scutclient[0].ifname) &	
	
}
	
logoff() {
	scutclient logoff	
}

start() {
	if [ $(uci get scutclient.@option[0].enable) -eq 0 ]
	then
		exit
	fi
	sleep $(uci get scutclient.@drcom[0].delay)
	logoff
	sleep 3
	auth
}	
	
stop() {	
	killall scutclient	
	logoff	
}	
	
restart() {	
	stop	
	auth	
}	
	
