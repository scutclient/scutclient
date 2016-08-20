#!/bin/sh /etc/rc.common	
	
START=99	
STOP=15	
	
	
auth() {	
	
	if [ $(uci get scutclient.@option[0].enable) -eq 0 ]	
	then	
		exit	
	fi	

	scutclient $(uci get scutclient.@scutclient[0].username) $(uci get scutclient.@scutclient[0].password) $(uci get network.wan.ifname) &
	
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

	if [[ $(ps | grep 'scutclient' | wc -l) -eq 0 ]] ;then
		killall scutclient	
	fi

	logoff	
}	
	
restart() {	
	stop	
	auth	
}	
	
