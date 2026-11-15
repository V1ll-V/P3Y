#!/bin/sh
set -eu

KIND_FILE="/run/wg/kind"
CONF="/run/wg/wg0.conf"
OVPN_CONF="/run/wg/client.ovpn"
OVPN_LOG="/run/wg/openvpn.log"
OVPN_PID_FILE="/run/wg/openvpn.pid"
DNS_FILE="/run/wg/dns"
READY_FILE="/run/wg/ready"
ORIG_RESOLV="/run/wg/resolv.orig"

KIND="wireguard"
if [ -f "$KIND_FILE" ]; then
  KIND=$(tr -d ' \t\r\n' < "$KIND_FILE")
fi

rm -f "$READY_FILE"

if [ -f /etc/resolv.conf ] && [ ! -f "$ORIG_RESOLV" ]; then
  cp /etc/resolv.conf "$ORIG_RESOLV"
fi

apply_dns() {
  dns_list="$1"
  if [ -z "$dns_list" ]; then
    return 0
  fi
  dns_count=$(printf '%s\n' "$dns_list" | grep -cE '[^[:space:]]' || true)
  if [ "$dns_count" -eq 0 ]; then
    return 0
  fi
  # Rewrite Docker's bind-mounted /etc/resolv.conf in-place (atomic truncate, never mv).
  {
    printf '%s\n' "$dns_list" | while IFS= read -r ns; do
      [ -n "$ns" ] && printf 'nameserver %s\n' "$ns"
    done
    if [ "$dns_count" -lt 2 ] && [ -f "$ORIG_RESOLV" ]; then
      grep -E '^(nameserver|search|options) ' "$ORIG_RESOLV" || true
    fi
  } > /etc/resolv.conf
}

OVPN_PID=""

cleanup() {
  rm -f "$READY_FILE"
  if [ -f "$ORIG_RESOLV" ]; then
    cat "$ORIG_RESOLV" > /etc/resolv.conf 2>/dev/null || true
  fi
  if [ "$KIND" = "openvpn" ]; then
    if [ -n "$OVPN_PID" ] && kill -0 "$OVPN_PID" 2>/dev/null; then
      kill "$OVPN_PID" 2>/dev/null || true
      wait "$OVPN_PID" 2>/dev/null || true
    elif [ -f "$OVPN_PID_FILE" ]; then
      pid=$(cat "$OVPN_PID_FILE" 2>/dev/null || true)
      if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
      fi
    fi
  else
    wg-quick down "$CONF" 2>/dev/null || true
  fi
  exit 0
}

trap cleanup TERM INT

if [ "$KIND" = "openvpn" ]; then
  if [ ! -f "$OVPN_CONF" ]; then
    echo "missing $OVPN_CONF" >&2
    exit 1
  fi
  chmod 600 "$OVPN_CONF"
  mkdir -p /dev/net
  if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200 2>/dev/null || true
  fi
  rm -f "$OVPN_LOG" "$OVPN_PID_FILE"
  openvpn --config "$OVPN_CONF" --script-security 0 --auth-nocache --writepid "$OVPN_PID_FILE" --log "$OVPN_LOG" &
  OVPN_PID=$!

  ready=0
  i=0
  while [ "$i" -lt 100 ]; do
    if ! kill -0 "$OVPN_PID" 2>/dev/null; then
      echo "openvpn exited before tunnel became ready" >&2
      cat "$OVPN_LOG" >&2 2>/dev/null || true
      exit 1
    fi
    if ip -4 -o addr show | grep -qE '[[:space:]](tun|tap)[0-9]+'; then
      ready=1
      break
    fi
    i=$((i + 1))
    sleep 0.25
  done
  if [ "$ready" -ne 1 ]; then
    echo "timed out waiting for openvpn tunnel interface" >&2
    cat "$OVPN_LOG" >&2 2>/dev/null || true
    kill "$OVPN_PID" 2>/dev/null || true
    exit 1
  fi

  merged_dns=""
  if [ -s "$DNS_FILE" ]; then
    merged_dns=$(cat "$DNS_FILE")
  fi
  if [ -s "$OVPN_LOG" ]; then
    pushed_dns=$(grep -oE 'dhcp-option DNS [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$OVPN_LOG" 2>/dev/null | awk '{print $3}' || true)
    if [ -n "$pushed_dns" ]; then
      if [ -n "$merged_dns" ]; then
        merged_dns=$(printf '%s\n%s\n' "$merged_dns" "$pushed_dns" | awk 'NF && !seen[$0]++')
      else
        merged_dns=$(printf '%s\n' "$pushed_dns" | awk 'NF && !seen[$0]++')
      fi
    fi
  fi
  apply_dns "$merged_dns"
else
  if [ ! -f "$CONF" ]; then
    echo "missing $CONF" >&2
    exit 1
  fi
  chmod 600 "$CONF"
  # Start WireGuard first so Endpoint hostnames resolve via the container's initial DNS.
  wg-quick up "$CONF"
  if [ -s "$DNS_FILE" ]; then
    apply_dns "$(cat "$DNS_FILE")"
  fi
fi

touch "$READY_FILE"

while true; do
  if [ "$KIND" = "openvpn" ] && [ -n "$OVPN_PID" ]; then
    if ! kill -0 "$OVPN_PID" 2>/dev/null; then
      echo "openvpn process exited unexpectedly" >&2
      rm -f "$READY_FILE"
      exit 1
    fi
  fi
  sleep 2 &
  wait $! || true
done
