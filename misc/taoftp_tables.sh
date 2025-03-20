#!/usr/bin/env bash
#
# A simple script to add/remove TFTP port-forwarding (UDP/69) to a remote host/port,
# while handling TFTP ephemeral ports.

if [[ $# -lt 1 ]]; then
  echo "Usage:"
  echo "  $0 add <REMOTE_IP> <REMOTE_PORT>"
  echo "  $0 remove"
  exit 1
fi

ACTION="$1"        # add or remove
REMOTE_IP="$2"     # e.g. 192.168.1.50
REMOTE_PORT="$3"   # e.g. 69 (if TFTP server is also using 69)
TABLENAME="TAOFTP"

# Load TFTP connection tracking helpers
modprobe nf_conntrack_tftp 2>/dev/null
modprobe nf_nat_tftp 2>/dev/null

# ----------------------------------------
# iptables Section
# ----------------------------------------
iptables_add() {
  echo ">>> Adding iptables TFTP rules..."

  iptables -t nat -N "$TABLENAME" 2>/dev/null
  iptables -t nat -A PREROUTING -p udp --dport 69 -j "$TABLENAME"
  iptables -t nat -A "$TABLENAME" -p udp --dport 69 -j DNAT --to-destination "$REMOTE_IP:$REMOTE_PORT"
  iptables -t raw -A PREROUTING -p udp --dport 69 -j CT --helper tftp
  iptables -A FORWARD -p udp -d "$REMOTE_IP" --dport "$REMOTE_PORT" -j ACCEPT
  iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

  echo ">>> iptables rules added. TFTP requests on UDP/69 will be forwarded to $REMOTE_IP:$REMOTE_PORT."
}
iptables_remove() {
  echo ">>> Removing iptables TFTP rules..."

  iptables -t nat -D PREROUTING -p udp --dport 69 -j MYTFTP 2>/dev/null
  iptables -t nat -F MYTFTP 2>/dev/null
  iptables -t nat -X MYTFTP 2>/dev/null
  iptables -t raw -D PREROUTING -p udp --dport 69 -j CT --helper tftp 2>/dev/null

  iptables -D FORWARD -p udp -d "$REMOTE_IP" --dport "$REMOTE_PORT" -j ACCEPT 2>/dev/null
  iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

  echo ">>> iptables TFTP rules removed."
}


if [[ "$ACTION" == "add" ]]; then
    if [[ -z "$REMOTE_IP" || -z "$REMOTE_PORT" ]]; then
    echo "Error: Missing remote IP/port for 'add' action."
    exit 1
    fi
    iptables_add
elif [[ "$ACTION" == "remove" ]]; then
    iptables_remove
else
    echo "Error: Unknown action '$ACTION'. Use add or remove."
    exit 1
fi


exit 0
