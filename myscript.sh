# 1. Recreate namespaces + veth
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

# 2. Disable checksum offload (needed again — doesn't persist)
sudo ip netns exec ns-alice ethtool -K veth-a tx off rx off
sudo ip netns exec ns-bob   ethtool -K veth-b tx off rx off

# 3. Sanity check
sudo ip netns exec ns-alice ping -c 2 10.200.1.2

# 4. Run the actual test
cd ~/QUIC-MLS-DeepSpace
sudo ip netns exec ns-bob ./target/debug/echo-server 10.200.1.2:4433 &
sleep 1
sudo ip netns exec ns-alice ./target/debug/echo-client 10.200.1.2:4433
