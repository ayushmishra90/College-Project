#!/usr/bin/env python3
"""
Mininet traffic generator (final):
 - uses RemoteController at 127.0.0.1:6653 (osken default)
 - creates a single simple topology with two hosts + one OVS switch (OpenFlow13)
 - toggles dataset/label_flag.txt to indicate attack windows
 - produces benign + SYN/UDP/ICMP attacks
"""
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time, os

MONITOR_INTERVAL = 30
LABEL_FILE = "dataset/label_flag.txt"

def write_label(val):
    os.makedirs("dataset", exist_ok=True)
    with open(LABEL_FILE, "w") as f:
        f.write("1" if val else "0")

def run():
    setLogLevel("info")
    controller = RemoteController("c0", ip="127.0.0.1", port=6653)
    net = Mininet(controller=controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info("*** Starting network\n")
    net.start()
    info("*** Waiting for controller and switch to fully connect (10s)\n")
    time.sleep(10)

    # ensure label = 0 (benign)
    write_label(0)

    info("*** Sending baseline benign traffic\n")
    h2.cmd("ping -c 5 10.0.0.1")
    # try iperf3 if installed
    h1.cmd("iperf3 -s &> /dev/null &")
    h2.cmd("iperf3 -c 10.0.0.1 -t 5 &> /dev/null &")
    time.sleep(5)

    info(f"*** Sleeping {MONITOR_INTERVAL} seconds to let controller capture benign interval\n")
    time.sleep(MONITOR_INTERVAL)

    # --- SYN flood window ---
    info("*** Starting SYN flood (label=1)\n")
    write_label(1)
    h2.cmd("hping3 -S --flood -p 80 10.0.0.1 &> /dev/null &")
    time.sleep(MONITOR_INTERVAL)
    h2.cmd("pkill -f hping3 || true")
    write_label(0)
    info("*** SYN flood finished\n")
    time.sleep(5)

    # --- UDP flood window ---
    info("*** Starting UDP flood (label=1)\n")
    write_label(1)
    h2.cmd("hping3 --udp --flood -p 80 10.0.0.1 &> /dev/null &")
    time.sleep(MONITOR_INTERVAL)
    h2.cmd("pkill -f hping3 || true")
    write_label(0)
    info("*** UDP flood finished\n")
    time.sleep(5)

    # --- ICMP flood window ---
    info("*** Starting ICMP flood (label=1)\n")
    write_label(1)
    h2.cmd("ping -f -c 300 10.0.0.1 &> /dev/null &")
    time.sleep(MONITOR_INTERVAL)
    h2.cmd("pkill -f ping || true")
    write_label(0)
    info("*** ICMP flood finished\n")

    # Final wait to allow controller to write last interval(s)
    info(f"*** Final sleep {MONITOR_INTERVAL} seconds to let controller flush data\n")
    time.sleep(MONITOR_INTERVAL)

    net.stop()
    info("*** Mininet stopped\n")

if __name__ == "__main__":
    run()
