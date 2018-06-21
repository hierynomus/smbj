#!/bin/bash
set -e

: ${SMB_USER:=smbuser}
: ${SMB_PASSWORD:=smbpassword}

for netdev in /sys/class/net/*; do
  netdev=${netdev##*/}
  if [[ $netdev != 'lo' ]]; then
    break
  fi
done
subnet=$(ip addr show $netdev | sed -n 's/.*inet \([0-9\.]*\/[0-9]*\) .*/\1/p')
ip_address=${subnet%%/*}

# Create DFS links
# - /public -> public share
# - /user -> user share
# - /firstfail-public -> first listed server fails, second -> public share
ln -s msdfs:${ip_address}\\public /opt/samba/dfs/public
ln -s msdfs:${ip_address}\\user /opt/samba/dfs/user
ln -s msdfs:192.0.2.1\\notthere,${ip_address}\\public /opt/samba/dfs/firstfail-public

exec "$@"
