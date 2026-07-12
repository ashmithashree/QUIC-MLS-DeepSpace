#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 <leo|geo|lunar|mars|clear> <namespace> <iface>"
    echo "example: sudo $0 leo ns-bob veth-b"
    exit 1
}

[ $# -eq 3 ] || usage
PROFILE="$1"
NS="$2"
IFACE="$3"

# LEO: 16ms OWD - measured, not derived. Kosek, Cech, Bajpai, Ott,
# "Exploring Proxying QUIC and HTTP/3 for Satellite Communication",
# IFIP Networking 2022 (arXiv:2205.01554) 

# GEO: 250ms OWD - speed-of-light derivation via a GEO relay
# (35,786km altitude) M. Kosek, H. Cech, V. Bajpai, and J. Ott, "Exploring Proxying QUIC and
# HTTP/3 for Satellite Communication," in Proc. IFIP Networking Conference,
# 2022. arXiv:2205.01554.

# Lunar: 1282ms OWD - speed-of-light calc, avg Earth-Moon distance
# 384,400km / c. - Jet Propulsion Laboratory, Solar System Dynamics, "LD (Lunar Distance),"
#NASA, https://ssd.jpl.nasa.gov/glossary/LD.html, accessed [today's date].

# Mars: 240000ms (4min) OWD - taken directly from Blanchet, "QUIC
# Profile for Deep Space" (draft-many-deepspace-quic-profile-00),
# stated range of 4-20min one-way light-time. 
case "$PROFILE" in
    leo)
        DELAY="16ms"
        JITTER="2ms"
        RATE="20mbit"
        LOSS="0.01%"
        ;;
    geo)
        DELAY="250ms"
        JITTER="5ms"
        RATE="20mbit"
        LOSS="0.01%"
        ;;
    lunar)
        DELAY="1282ms"
        JITTER="20ms"
        RATE="2mbit"
        LOSS="0.1%"
        ;;
    mars)
        DELAY="240000ms"
        JITTER="0ms"
        RATE="500kbit"
        LOSS="1%"
        ;;
    clear)
        sudo ip netns exec "$NS" tc qdisc del dev "$IFACE" root 2>/dev/null || true
        echo "cleared netem on $IFACE in $NS"
        exit 0
        ;;
    *)
        usage
        ;;
esac

sudo ip netns exec "$NS" tc qdisc del dev "$IFACE" root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc add dev "$IFACE" root netem \
    delay "$DELAY" "$JITTER" distribution normal \
    rate "$RATE" \
    loss "$LOSS"

echo "applied $PROFILE to $IFACE in $NS: delay=$DELAY±$JITTER rate=$RATE loss=$LOSS"
sudo ip netns exec "$NS" tc qdisc show dev "$IFACE"