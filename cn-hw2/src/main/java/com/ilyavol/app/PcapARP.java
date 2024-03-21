package com.ilyavol.app;

import org.pcap4j.core.*;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.EtherType;

import org.pcap4j.util.MacAddress;
import org.pcap4j.util.ByteArrays;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.io.EOFException;
import java.util.concurrent.TimeoutException;


public class PcapARP {
    private final String hostIP;
    private final MacAddress SRC_MAC;
    private final int timeout = 60000; 
    private final int snapLen = 65536;
    private final PcapNetworkInterface.PromiscuousMode mode =
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

    private static MacAddress resolvedAddr;

    PcapARP(String ip, String mac) {
        this.hostIP  = ip;
        this.SRC_MAC  = MacAddress.getByName(mac);
    }

    public void printMACbyIP(String ip) throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               InetAddress addr = InetAddress.getByName(this.hostIP);
               PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

               PcapHandle handle = nif.openLive(this.snapLen, this.mode, this.timeout);
               PcapHandle sendHandle = nif.openLive(this.snapLen, this.mode, this.timeout);

               InetAddress dest_ip = InetAddress.getByName(ip);

               ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
               try {
                   arpBuilder
                       .hardwareType(ArpHardwareType.ETHERNET)
                       .protocolType(EtherType.IPV4)
                       .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                       .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                       .operation(ArpOperation.REQUEST)
                       .srcHardwareAddr(this.SRC_MAC)
                       .srcProtocolAddr(InetAddress.getByName(this.hostIP))
                       .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                       .dstProtocolAddr(dest_ip);
               } catch (UnknownHostException e) {
                   throw new IllegalArgumentException(e);
               }

               EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
               etherBuilder
                   .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                   .srcAddr(SRC_MAC)
                   .type(EtherType.ARP)
                   .payloadBuilder(arpBuilder)
                   .paddingAtBuild(true);

               Packet p = etherBuilder.build();
               System.out.println(p);
               sendHandle.sendPacket(p);

               long start = System.currentTimeMillis();
               long end = start + this.timeout; // delay 

               System.out.println("Searching...\nTime limit is: " + this.timeout + " ms\n");
               while(System.currentTimeMillis() < end) {

                   Packet packet = handle.getNextPacketEx();
                   ArpPacket arpPacket = packet.get(ArpPacket.class);

                   if(arpPacket !=null
                           && arpPacket.getHeader().getOperation().equals(ArpOperation.REPLY)
                           && arpPacket.getHeader().getSrcProtocolAddr().equals(dest_ip)) {
                       PcapARP.resolvedAddr = arpPacket.getHeader().getSrcHardwareAddr();
                       break;
                           }
                   
               }


               if (PcapARP.resolvedAddr == null) {
                   System.out.println("Device not found");
               } else {
                   System.out.println("For ip:\t" + ip + 
                           "\nFound mac address:\t " + PcapARP.resolvedAddr);
               }
    }

    public void printAllARPs() throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               InetAddress addr = InetAddress.getByName(this.hostIP);
               PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

               PcapNetworkInterface.PromiscuousMode mode =
                   PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

               PcapHandle handle = nif.openLive(this.snapLen, mode, this.timeout);

               while(true) {
                   Packet packet = handle.getNextPacketEx();
                   ArpPacket arpPacket = packet.get(ArpPacket.class);
                   if(arpPacket !=null) {
                       System.out.println(arpPacket);
                   }
               }
    }

}

