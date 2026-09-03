#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

set -eu

filter_table="mindrove_bridge"
nat_table="mindrove_bridge_nat"
state_file="/run/mindrove-bridge-ip-forward.state"
host_ip="172.31.242.1"
board_ip="192.168.4.1"
stream_port="4210"

usage() {
    echo "Usage: $0 up <host-interface> <wifi-interface> | down | status" >&2
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this command as root (for example, with sudo)." >&2
        exit 77
    fi
}

validate_interface_name() {
    case "$1" in
        ""|*[!A-Za-z0-9_.:-]*)
            echo "Unsafe or empty interface name: $1" >&2
            exit 64
            ;;
    esac
    if [ ! -e "/sys/class/net/$1" ]; then
        echo "Network interface does not exist: $1" >&2
        exit 69
    fi
}

table_exists() {
    nft list table "$1" "$2" >/dev/null 2>&1
}

remove_tables() {
    if table_exists inet "$filter_table"; then
        nft delete table inet "$filter_table"
    fi
    if table_exists ip "$nat_table"; then
        nft delete table ip "$nat_table"
    fi
}

restore_forwarding() {
    if [ -f "$state_file" ]; then
        previous_value="$(sed -n '1p' "$state_file")"
        case "$previous_value" in
            0|1)
                sysctl -q -w "net.ipv4.ip_forward=$previous_value"
                ;;
        esac
        rm -f "$state_file"
    fi
}

bring_up() {
    require_root
    if [ "$#" -ne 2 ]; then
        usage
        exit 64
    fi

    host_interface="$1"
    wifi_interface="$2"
    validate_interface_name "$host_interface"
    validate_interface_name "$wifi_interface"

    for command_name in nft ip sysctl sed; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            echo "Required command is missing: $command_name" >&2
            exit 69
        fi
    done

    if ! ip -4 address show dev "$host_interface" | grep -q "172\.31\.242\.2/24"; then
        echo "$host_interface must have 172.31.242.2/24 before routing is enabled." >&2
        exit 69
    fi
    if ! ip -4 route get "$board_ip" oif "$wifi_interface" >/dev/null 2>&1; then
        echo "$board_ip is not reachable through $wifi_interface; join the MindRove AP first." >&2
        exit 69
    fi

    if [ ! -f "$state_file" ]; then
        sysctl -n net.ipv4.ip_forward >"$state_file"
        chmod 600 "$state_file"
    fi

    remove_tables
    sysctl -q -w net.ipv4.ip_forward=1

    nft add table inet "$filter_table"
    nft "add chain inet $filter_table forward { type filter hook forward priority filter; policy drop; }"
    nft add rule inet "$filter_table" forward \
        iifname "$host_interface" oifname "$wifi_interface" \
        ip saddr "$host_ip" ip daddr "$board_ip" accept
    nft add rule inet "$filter_table" forward \
        iifname "$wifi_interface" oifname "$host_interface" \
        ip saddr "$board_ip" ip daddr "$host_ip" \
        ct state established,related accept
    nft add rule inet "$filter_table" forward \
        iifname "$wifi_interface" oifname "$host_interface" \
        ip saddr "$board_ip" ip daddr "$host_ip" \
        udp dport "$stream_port" accept

    nft add table ip "$nat_table"
    nft "add chain ip $nat_table prerouting { type nat hook prerouting priority dstnat; policy accept; }"
    nft "add chain ip $nat_table postrouting { type nat hook postrouting priority srcnat; policy accept; }"
    nft add rule ip "$nat_table" prerouting \
        iifname "$wifi_interface" ip saddr "$board_ip" \
        udp dport "$stream_port" dnat to "$host_ip:$stream_port"
    nft add rule ip "$nat_table" postrouting \
        iifname "$host_interface" oifname "$wifi_interface" \
        ip saddr "$host_ip" ip daddr "$board_ip" masquerade

    echo "MindRove route enabled: $host_ip -> $board_ip via $wifi_interface"
    echo "No default route or DNS setting was changed."
}

bring_down() {
    require_root
    remove_tables
    restore_forwarding
    echo "MindRove forwarding rules removed."
}

show_status() {
    echo "IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward)"
    if table_exists inet "$filter_table" && table_exists ip "$nat_table"; then
        echo "MindRove nftables rules: active"
    else
        echo "MindRove nftables rules: inactive"
    fi
}

action="${1:-}"
case "$action" in
    up)
        shift
        bring_up "$@"
        ;;
    down)
        if [ "$#" -ne 1 ]; then
            usage
            exit 64
        fi
        bring_down
        ;;
    status)
        if [ "$#" -ne 1 ]; then
            usage
            exit 64
        fi
        show_status
        ;;
    *)
        usage
        exit 64
        ;;
esac

