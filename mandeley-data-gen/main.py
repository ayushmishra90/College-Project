#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.cli import CLI

class SimpleTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)

def run():
    topo = SimpleTopo()
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653))
    net.start()
    print("Network started. You can ping between hosts.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
