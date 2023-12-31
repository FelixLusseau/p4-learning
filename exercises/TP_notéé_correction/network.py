from p4utils.mininetlib.network_API import NetworkAPI
import time
from threading import Thread
from mininet.link import TCLink

net = NetworkAPI()

# Network general options
net.setLogLevel("info")

net.addHost("h1")
net.addHost("h2")

# Network definition
net.addP4Switch("s1")
net.addP4Switch("s2")
net.addP4Switch("s3")
net.addP4Switch("s4")
net.addP4Switch("s5")
net.addP4Switch("s6")


net.addLink("h1", "s1")
net.addLink("h2", "s6")
net.addLink("s1", "s2")
net.addLink("s2", "s3")
net.addLink("s2", "s6")
net.addLink("s3", "s4")
net.addLink("s4", "s6")
net.addLink("s2", "s5")
net.addLink("s5", "s6")

net.setP4SourceAll("p4src/main.p4")


# Assignment strategy
net.l3()

# Nodes general options
net.enablePcapDumpAll()
net.enableLogAll()
net.enableCli()

net.startNetwork()
