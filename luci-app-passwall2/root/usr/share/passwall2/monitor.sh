#!/bin/sh

. /usr/share/passwall2/utils.sh
LOCK_FILE=${LOCK_PATH}/${CONFIG}_monitor.lock

ENABLED=$(config_n_get @global[0] enabled 0)
[ "$ENABLED" != 1 ] && return 1
ENABLED=$(config_n_get @global_delay[0] start_daemon 0)
[ "$ENABLED" != 1 ] && return 1
# 与 init 脚本共用服务互斥锁：服务操作期间不检查、不重新拉起进程。
exec 8>"${LOCK_PATH}/${CONFIG}.flock"
sleep 58s
while [ "$ENABLED" -eq 1 ]; do
	[ -f "$LOCK_FILE" ] && {
		sleep 6s
		continue
	}
	if ! flock -xn 8; then
		sleep 6s
		continue
	fi
	touch $LOCK_FILE
	[ -d ${TMP_SCRIPT_FUNC_PATH} ] && {
		for filename in $(ls ${TMP_SCRIPT_FUNC_PATH} | grep -v "^_"); do
			cmd=$(cat ${TMP_SCRIPT_FUNC_PATH}/${filename})
			cmd_check=$(echo $cmd | awk -F '>' '{print $1}')
			escape_cmd="$(echo $cmd_check | sed 's/[^a-zA-Z0-9]/\\&/g')"
			icount=$(busybox pgrep -f "${escape_cmd}" | wc -l)
			if [ $icount = 0 ]; then
				log 0 "${cmd} crashed, restarting."
				# 重新拉起的进程不继承锁描述符。
				eval $(echo "nohup ${cmd} 2>&1 &") >/dev/null 2>&1 8>&- &
			fi
		done
	}
	
	rm -f $LOCK_FILE
	flock -u 8
	sleep 58s
done
