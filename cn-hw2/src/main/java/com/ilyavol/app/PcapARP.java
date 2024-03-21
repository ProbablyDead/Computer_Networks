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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class PcapARP {
    private final String hostIP;
    private final MacAddress thisMAC;
    private final int timeout = 60000; 
    private final int snapLen = 65536;
    private final PcapNetworkInterface.PromiscuousMode mode =
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

    private static MacAddress resolvedAddr;

    PcapARP(String ip, String mac) {
        this.hostIP  = ip;
        this.thisMAC  = MacAddress.getByName(mac);
    }

    // 1: Print all captured ARP packets
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

    // 2: Print MAC address of device in network by IP
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
                       .srcHardwareAddr(this.thisMAC)
                       .srcProtocolAddr(InetAddress.getByName(this.hostIP))
                       .dstHardwareAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                       .dstProtocolAddr(dest_ip);
               } catch (UnknownHostException e) {
                   throw new IllegalArgumentException(e);
               }

               EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
               etherBuilder
                   .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                   .srcAddr(thisMAC)
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

    public void printStatistic(long TimeMS) throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               InetAddress addr = InetAddress.getByName(this.hostIP);
               PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);

               PcapHandle handle = nif.openLive(this.snapLen, this.mode, (int)TimeMS);

               long ethernetCount = 0,
                    arpCount = 0,
                    broadcasts = 0,
                    arpToMe = 0,
                    ethernetToMe = 0,
                    ethernetNOTMe = 0,
                    dataSizeInBytes = 0;

               HashSet<String> uniqueMACs = new HashSet<>();
               HashMap<String, Integer> pairOfMacs = new HashMap<>();

               long end = Long.MAX_VALUE;
               boolean flag = false;

               System.out.println("Loading...");

               while (System.currentTimeMillis() < end) {
                   Packet packet = handle.getNextPacketEx();

                   if (!flag) { // delay 
                       long start = System.currentTimeMillis();
                       end = start + TimeMS; 
                       flag = true;
                   }

                   EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

                   if (ethernetPacket == null) {
                       continue;
                   }

                   // Data size
                   dataSizeInBytes += ethernetPacket.length() - 18; // 18 = header (14 bytes) + checksum(4 bytes)
                                                                    // i hope this is what You asked for :)
                   

                   // Ethernet frames count 
                   ethernetCount++;
                   EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();

                   String srcStr = header.getSrcAddr().toString(); 
                   String dstStr = header.getDstAddr().toString(); 

                   // Most frequent pairs of macs
                   Boolean cond = srcStr.compareTo(dstStr) > 0;

                   String key = (cond ? srcStr : dstStr) + " / " + (!cond ? srcStr : dstStr);
                   pairOfMacs.put(key, pairOfMacs.getOrDefault(key, 0) + 1);

                   if (header.getDstAddr().equals(this.thisMAC)) {
                       // Ethernet frames to me  
                       ethernetToMe++;
                   } else if (!header.getSrcAddr().equals(this.thisMAC)) {
                       // Ethernet frames not from and to me  
                       ethernetNOTMe++;
                   }

                   if (header.getDstAddr().equals(MacAddress.ETHER_BROADCAST_ADDRESS)) {
                       // Broadcast ethernet messages
                       broadcasts++;
                   }

                   // ARP
                   if (ethernetPacket.contains(ArpPacket.class)) {
                       // ARP packets count
                       arpCount++;

                       ArpPacket.ArpHeader arpHeader = ethernetPacket.get(ArpPacket.class).getHeader();
                       if (arpHeader.getDstProtocolAddr().equals(addr)) {
                           // ARP to me packets count
                           arpToMe++;
                       }
                   }

                   // Unique MACs
                   uniqueMACs.add(header.getDstAddr().toString());
                   uniqueMACs.add(header.getSrcAddr().toString());
               }

               System.out.println("\n" + "_".repeat(20) + "Stats" + "_".repeat(20) + "\n");
               System.out.println(" 1. Received ETHERNET frames:\t" + ethernetCount);
               System.out.println("\n 2. Received ARP packets:\t" + arpCount);
               System.out.println("\n 3. Unique MACs:\t" + uniqueMACs.size());
               System.out.println("\n 4. Broadcast frames count:\t" + broadcasts);
               System.out.println("\n 5. Ethernet frame to this device:\t" + ethernetToMe);
               System.out.println("\t5.1 From which ARP is:\t" + arpToMe);
               System.out.println("\n 6. Ethernet which source and destination is not this device:\t" + ethernetNOTMe);
               System.out.println("\n 7. Data resieved (in bytes)\t" + dataSizeInBytes);
               System.out.println("\n 8. The most frequent pairs of mac addresses:\n");

               pairOfMacs.entrySet().stream()
                   .sorted(Collections.reverseOrder(Map.Entry.comparingByValue()))
                   .limit(10)
                   .forEach((val) -> {
                       System.out.println("\t" + val.getKey() + " = " + val.getValue());
                   });
    }

}

