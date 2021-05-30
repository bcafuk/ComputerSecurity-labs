#!/bin/sh 

PATH="/sbin:/usr/sbin:/bin:/usr/bin"
export PATH

reset_iptables() {
  iptables -P OUTPUT  DROP
  iptables -P INPUT   DROP
  iptables -P FORWARD DROP

cat /proc/net/ip_tables_names | while read table; do
  iptables -t $table -L -n | while read c chain rest; do
      if test "X$c" = "XChain" ; then
        iptables -t $table -F $chain
      fi
  done
  iptables -t $table -X
done
}

script_body() {
    # accept established sessions
    iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT 
    iptables -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT 
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # accept only RIP responses and only from router FW
    iptables -A INPUT -p udp --dport 520 -s 198.51.100.1 -m u32 --u32 "28&0xFFFFFFFF=0x02020000" -j ACCEPT

    # ================ Table 'nat',  rule set NAT
    # 
    echo "... no need to translate between DMZ and internal net"
    #
    iptables -t nat -A POSTROUTING  -s 198.51.100.0/24  -d 10.0.1.0/24  -j ACCEPT
    iptables -t nat -A PREROUTING  -s 198.51.100.0/24  -d 10.0.1.0/24  -j ACCEPT
    iptables -t nat -A POSTROUTING  -s 10.0.1.0/24  -d 198.51.100.0/24  -j ACCEPT
    iptables -t nat -A PREROUTING  -s 10.0.1.0/24  -d 198.51.100.0/24  -j ACCEPT

    # 
    echo "... translate source address for outgoing connections"
    #
    iptables -t nat -A POSTROUTING -o eth0   -s 10.0.1.0/24  -j SNAT --to-source 198.51.100.2



    # ================ Table 'filter', rule set Policy
    # 
    echo "... anti spoofing rule (eth0)"
    #
    iptables -A INPUT -i eth0   -s 198.51.100.2   -m state --state NEW  -j DROP
    #
    # <--- Dodajte ili modificirajte pravila 
    #
    iptables -A FORWARD -i eth0   -s 198.51.100.2   -m state --state NEW  -j DROP
    #
    # <--- Dodajte ili modificirajte pravila 
    #

    # 
    echo "... loopback"
    # 
    iptables -A INPUT -i lo   -m state --state NEW  -j ACCEPT
    iptables -A OUTPUT -o lo   -m state --state NEW  -j ACCEPT

    # 
    echo "... SSH Access to firewall FW_int is permitted only from int1 (on LAN)"
    #
    # <--- Dodajte pravila 
    #

    #
    echo "... SSH Access to mail (on LAN) is permitted only from mail-relay (on DMZ)"
    #
    # <--- Dodajte pravila
    #

    # 
    echo "... permit a mail relay located on DMZ to connect to internal mail server"
    #
    # <--- Dodajte pravila 
    #

    # 
    echo "... permit access from LAN to Internet and DMZ"
    #
    # <--- Dodajte pravila 
    #
}

block_action() {
    reset_iptables
}

stop_action() {
    reset_iptables
    iptables -P OUTPUT  ACCEPT
    iptables -P INPUT   ACCEPT
    iptables -P FORWARD ACCEPT
}

check_iptables() {
    IP_TABLES="$1"
    [ ! -e $IP_TABLES ] && return 151
    NF_TABLES=$(cat $IP_TABLES 2>/dev/null)
    [ -z "$NF_TABLES" ] && return 152
    return 0
}

# See how we were called.
# For backwards compatibility missing argument is equivalent to 'start'

cmd=$1
test -z "$cmd" && {
    cmd="start"
}

case "$cmd" in
    start)
        reset_iptables 
        script_body
        echo 1 > /proc/sys/net/ipv4/ip_forward
        RETVAL=$?
        ;;

    stop)
        stop_action
        RETVAL=$?
        ;;

    block)
        block_action
        RETVAL=$?
        ;;

    reload)
        $0 stop
        $0 start
        RETVAL=$?
        ;;

    *)
        echo "Usage $0 [start|stop|block|reload]"
        ;;
esac

