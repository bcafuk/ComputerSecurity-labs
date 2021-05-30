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

    # 
    echo "... anti-spoofing rule (eth0)"
    # 
    iptables -A INPUT -i eth0   -s 198.51.100.0/24  -m state --state NEW  -j DROP
    iptables -A INPUT -i eth0   -s 10.0.0.0/8   -m state --state NEW  -j DROP
    # u primjeru, za "javne" adrese u "Internetu" koristimo TEST-NET[1,2,3] te ih
    # stoga necemo filtrirati anti-spoofing pravilima
    #
    # <--- Dodajte ili modificirajte pravila 
    #
    iptables -A FORWARD -i eth0   -s 192.0.2.1   -m state --state NEW  -j DROP
    #
    # <--- Dodajte ili modificirajte pravila 
    #

    # 
    echo "... accept all on loopback"
    # 
    iptables -A INPUT -i lo   -m state --state NEW  -j ACCEPT
    iptables -A OUTPUT -o lo   -m state --state NEW  -j ACCEPT

    # 
    echo "... ssh access to firewall only from int1"
    # 
    # <--- Dodajte pravila 
    #

    # 
    echo "... firewall uses one of the machines on internal network for DNS"
    #
    # <--- Dodajte pravila 
    #

    # 
    echo "... RIP on FWs external interface"
    #
    iptables -A INPUT -i eth0  -p udp -m udp -s 192.0.2.100  -d 224.0.0.9  --sport 520 --dport 520   -m state --state NEW  -j ACCEPT
    iptables -A OUTPUT         -p udp -m udp -s 192.0.2.1    -d 224.0.0.9  --sport 520 --dport 520   -m state --state NEW  -j ACCEPT

    # 
    echo "... RIP on FWs internal interface"
    #
    iptables -A INPUT -i eth2  -p udp -m udp -s 198.51.100.2 -d 224.0.0.9  --sport 520 --dport 520   -m state --state NEW  -j ACCEPT
    iptables -A OUTPUT         -p udp -m udp -s 198.51.100.1 -d 224.0.0.9  --sport 520 --dport 520   -m state --state NEW  -j ACCEPT

    # 
    echo "... mail relay on DMZ can accept connections from hosts on the Internet"
    #
    # <--- Dodajte pravila 
    #

    # 
    echo "... mail relay needs DNS and can connect to mail servers on the Internet"
    #
    # <--- Dodajte pravila 
    #

    # 
    echo "... web server on DMZ must be reachable from the Internet"
    #
    # <--- Dodajte pravila 
    #

    echo "... SSH Access to mail-relay (on DMZ) is permitted only on port 1111"
    #
    # <--- Dodajte pravila
    #

    # 
    echo "... access from the internal NAT to the Internet"
    #
    iptables -A FORWARD  -s 198.51.100.2/32   -m state --state NEW  -j ACCEPT
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

# missing argument is equivalent to 'start'
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

