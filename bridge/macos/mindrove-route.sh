#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

set -eu

board_ip="192.168.4.1"

usage() {
    echo "Usage: $0 up <vm-address> | down <vm-address> | status" >&2
}

validate_ipv4() {
    candidate="$1"
    if ! printf '%s\n' "$candidate" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1
            }
        }
    '; then
        echo "Invalid IPv4 address: $candidate" >&2
        exit 64
    fi
}

route_gateway() {
    route -n get "$board_ip" 2>/dev/null | awk '/gateway:/{ print $2; exit }'
}

route_destination() {
    route -n get "$board_ip" 2>/dev/null | awk '/^destination:/{ print $2; exit }'
}

bring_up() {
    vm_address="$1"
    validate_ipv4 "$vm_address"

    current_destination="$(route_destination || true)"
    current_gateway="$(route_gateway || true)"
    if [ "$current_destination" = "$board_ip" ] && [ "$current_gateway" = "$vm_address" ]; then
        echo "MindRove host route is already active through $vm_address."
        return
    fi
    if [ "$current_destination" = "$board_ip" ]; then
        echo "$board_ip currently resolves through $current_gateway; refusing to replace that route." >&2
        echo "Inspect 'route -n get $board_ip' and remove only the route you intend to replace." >&2
        exit 73
    fi

    sudo route -n add -host "$board_ip" "$vm_address"
    echo "Added only $board_ip through VM $vm_address."
    route -n get "$board_ip"
}

bring_down() {
    vm_address="$1"
    validate_ipv4 "$vm_address"

    current_destination="$(route_destination || true)"
    current_gateway="$(route_gateway || true)"
    if [ "$current_destination" != "$board_ip" ]; then
        echo "No dedicated host route for $board_ip is active."
        return
    fi
    if [ "$current_gateway" != "$vm_address" ]; then
        echo "$board_ip uses $current_gateway, not $vm_address; refusing to delete it." >&2
        exit 73
    fi

    sudo route -n delete -host "$board_ip" "$vm_address"
    echo "Removed the MindRove host route through $vm_address."
}

show_status() {
    echo "Default route:"
    route -n get default
    echo
    echo "MindRove route:"
    route -n get "$board_ip"
}

action="${1:-}"
case "$action" in
    up|down)
        if [ "$#" -ne 2 ]; then
            usage
            exit 64
        fi
        if [ "$action" = "up" ]; then
            bring_up "$2"
        else
            bring_down "$2"
        fi
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
