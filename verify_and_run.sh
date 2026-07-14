#!/usr/bin/env bash
set -euo pipefail
cd ~/QUIC-MLS-DeepSpace

echo "=== 1. Confirm the GSO fix is actually in the source files ==="
grep -n "enable_segmentation_offload" echo-server/src/lib.rs echo-client/src/lib.rs \
    || { echo "FIX NOT PRESENT — edits were not saved. Stop here and re-apply them."; exit 1; }

echo
echo "=== 2. Kill any stale server processes bound to the port ==="
pkill -f echo-server 2>/dev/null || true
sleep 1

echo
echo "=== 3. Clean rebuild, watching for compile errors ==="
cargo build 2>&1 | tail -40

echo
echo "=== 4. Confirm both binaries are fresh (timestamp should be seconds old) ==="
ls -la --time-style=full-iso target/debug/echo-server target/debug/echo-client

echo
echo "=== 5. Recreate namespaces + veth cleanly ==="
sudo ip netns del ns-alice 2>/dev/null || true
sudo ip netns del ns-bob   2>/dev/null || true
sudo ip netns add ns-alice
sudo ip netns add ns-bob
sudo ip link add veth-a type veth peer name veth-b
sudo ip link set veth-a netns ns-alice
sudo ip link set veth-b netns ns-bob
sudo ip netns exec ns-alice ip addr add 10.200.1.1/24 dev veth-a
sudo ip netns exec ns-bob   ip addr add 10.200.1.2/24 dev veth-b
sudo ip netns exec ns-alice ip link set veth-a up
sudo ip netns exec ns-bob   ip link set veth-b up
sudo ip netns exec ns-alice ip link set lo up
sudo ip netns exec ns-bob   ip link set lo up

echo
echo "=== 6. Re-apply checksum offload disable on the FRESH interfaces ==="
sudo ip netns exec ns-alice ethtool -K veth-a tx off rx off
sudo ip netns exec ns-bob   ethtool -K veth-b tx off rx off

echo
echo "=== 7. Confirm offload settings actually took on THESE interfaces ==="
sudo ip netns exec ns-alice ethtool -k veth-a | grep -E "tx-checksum|rx-checksum"
sudo ip netns exec ns-bob   ethtool -k veth-b | grep -E "tx-checksum|rx-checksum"

echo
echo "=== 8. Sanity check routing (ICMP) ==="
sudo ip netns exec ns-alice ping -c 2 10.200.1.2

echo
echo "=== Setup complete. Now run the server, tcpdump, and client manually in separate terminals: ==="
echo "  Terminal 1: sudo ip netns exec ns-bob tcpdump -ni veth-b udp port 4433"
echo "  Terminal 2: sudo ip netns exec ns-bob ./target/debug/echo-server 10.200.1.2:4433"
echo "  Terminal 3: sudo ip netns exec ns-alice ./target/debug/echo-client 10.200.1.2:4433"
