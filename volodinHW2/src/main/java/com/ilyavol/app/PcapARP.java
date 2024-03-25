package com.ilyavol.app;

import java.io.EOFException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

public class PcapARP {
    private static MacAddress resolvedAddr;
    private final InetAddress IP;
    private final MacAddress MAC; 
    private final int TIMEOUT = 2000;
    private final int CONNECTION_TIMEOUT = 1000;
    private final int SNAP_LEN = 65536;

    private final PcapNetworkInterface.PromiscuousMode MODE =
        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

    PcapARP(String ip, String mac) throws UnknownHostException {
        this.IP  = InetAddress.getByName(ip);
        this.MAC  = MacAddress.getByName(mac);
    }

    /**
     * 1) Print all captured ARP packets
     * @throws UnknownHostException
     * @throws PcapNativeException
     * @throws EOFException
     * @throws TimeoutException
     * @throws NotOpenException
     */
    public void printAllARPs() throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               PcapNetworkInterface nif = Pcaps.getDevByAddress(this.IP);

               PcapHandle handle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);

               while(true) {
                   Packet packet = handle.getNextPacketEx();
                   ArpPacket arpPacket = packet.get(ArpPacket.class);
                   if(arpPacket !=null) {
                       System.out.println(arpPacket);
                   }
               }
    }

    /**
     * 2) Return Mac address by ip address
     * @param ip IP for mac address search
     * @return Mac address or null, if not found
     * @throws UnknownHostException
     * @throws PcapNativeException
     * @throws EOFException
     * @throws TimeoutException
     * @throws NotOpenException
     */
    public String getMACbyIP(String ip) throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               InetAddress dest_ip = InetAddress.getByName(ip);

               PcapNetworkInterface nif = Pcaps.getDevByAddress(this.IP);

               PcapHandle handle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);
               PcapHandle sendHandle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);

               sendHandle.sendPacket(this.buildArpPacket(
                           ArpOperation.REQUEST,
                           this.MAC,
                           this.IP, 
                           MacAddress.ETHER_BROADCAST_ADDRESS,
                           dest_ip));

               long start = System.currentTimeMillis();
               long end = start + this.TIMEOUT; // Delay 

               System.out.println("Searching...\nTime limit is: " + this.TIMEOUT + " ms\n");
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

               return PcapARP.resolvedAddr != null ? PcapARP.resolvedAddr.toString() : null;
    }

    /**
     * 3) Print stastic
     * @param TimeMS Delay (ms.)
     * @throws UnknownHostException
     * @throws PcapNativeException
     * @throws EOFException
     * @throws TimeoutException
     * @throws NotOpenException
     */
    public void printStatistic(long TimeMS) throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               PcapNetworkInterface nif = Pcaps.getDevByAddress(this.IP);

               PcapHandle handle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);

               long ethernetCount = 0,
                    arpCount = 0,
                    broadcasts = 0,
                    arpToMe = 0,
                    ethernetToMe = 0,
                    ethernetNOTMe = 0,
                    dataSizeInBytes = 0;

               HashSet<String> uniqueMACs = new HashSet<>();
               HashMap<String, Integer> pairOfMacs = new HashMap<>();

               long start = System.currentTimeMillis();
               long end = start + TimeMS; 

               System.out.println("Loading...");

               while (System.currentTimeMillis() < end) {
                   Packet packet = handle.getNextPacketEx();

                   EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

                   if (ethernetPacket == null) {
                       continue;
                   }

                   // Data size
                   dataSizeInBytes += ethernetPacket.length() - 18; // 18 = header (14 bytes) + checksum(4 bytes)

                   // Ethernet frames count 
                   ethernetCount++;
                   EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();

                   String srcStr = header.getSrcAddr().toString(); 
                   String dstStr = header.getDstAddr().toString(); 

                   // Most frequent pairs of macs
                   Boolean cond = srcStr.compareTo(dstStr) > 0;

                   String key = (cond ? srcStr : dstStr) + " / " + (!cond ? srcStr : dstStr);
                   pairOfMacs.put(key, pairOfMacs.getOrDefault(key, 0) + 1);

                   if (header.getDstAddr().equals(this.MAC)) {
                       // Ethernet frames to me  
                       ethernetToMe++;
                   } else if (!header.getSrcAddr().equals(this.MAC)) {
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
                       if (arpHeader.getDstProtocolAddr().equals(this.IP)) {
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
               System.out.println();
    }

    /**
     * 4) Check if the ip address is in use by another device in the same network
     * @return
     * @throws UnknownHostException
     * @throws PcapNativeException
     * @throws EOFException
     * @throws TimeoutException
     * @throws NotOpenException
     */
    public String getDuplicateIP() throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
               PcapNetworkInterface nif = Pcaps.getDevByAddress(this.IP);

               MacAddress macToCheck = this.MAC;
               // InetAddress ipToCheck = this.IP;
               InetAddress ipToCheck = InetAddress.getByName("10.255.196.90"); // Test

               PcapHandle sendHandle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);
               PcapHandle handle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);

               sendHandle.sendPacket(
                       this.buildArpPacket(ArpOperation.REQUEST, 
                           macToCheck, 
                           ipToCheck, 
                           MacAddress.ETHER_BROADCAST_ADDRESS, 
                           ipToCheck)
                       );

               System.out.println("Searching...\nTime limit is: " + this.TIMEOUT + " ms\n");

               long start = System.currentTimeMillis();
               long end = start + this.TIMEOUT; // Delay 

               while(System.currentTimeMillis() < end) {

                   Packet packet = handle.getNextPacketEx();
                   ArpPacket arpPacket = packet.get(ArpPacket.class);

                   if (arpPacket == null) { continue; }

                   ArpPacket.ArpHeader header = arpPacket.getHeader();

                   // If we get some arp reply, that contains
                   // equal source and destination IPs with different mac addresses,
                   // then this an ip collision (example is in docs)
                   if(header.getOperation().equals(ArpOperation.REPLY) 
                           && header.getSrcProtocolAddr().equals(ipToCheck)
                           && header.getDstProtocolAddr().equals(ipToCheck)
                           && header.getDstHardwareAddr().equals(macToCheck)
                           && !this.MAC.equals(header.getSrcHardwareAddr()))
                   {
                       return header.getSrcHardwareAddr().toString();
                   }
               }
               return null;
    }

    /**
     * 5) Send targeted arp messages
     * @throws PcapNativeException
     * @throws NotOpenException
     */
    public void sendTargetedMessages () throws PcapNativeException, NotOpenException {
        PcapNetworkInterface nif = Pcaps.getDevByAddress(this.IP);

        PcapHandle handle = nif.openLive(this.SNAP_LEN, this.MODE, this.CONNECTION_TIMEOUT);

        InetAddress ipTo;
		try {
			ipTo = InetAddress.getByName("10.255.197.20"); // Test
		} catch (UnknownHostException e) {
            System.out.println("No such ip");
            return;
		} 
        MacAddress macTo = MacAddress.getByName("70:89:76:9d:92:c2"); // Test

        handle.sendPacket( // Arp targeted request
                this.buildArpPacket(
                    ArpOperation.REQUEST,
                    this.MAC, 
                    this.IP,
                    macTo,
                    ipTo)
                );

        handle.sendPacket( // Arp targeted reply
                this.buildArpPacket(
                    ArpOperation.REPLY,
                    this.MAC, 
                    this.IP,
                    macTo,
                    ipTo)
                );

        System.out.println("Complete!");
    }

    /** Build arp packet
     * @param operation Arp operation
     * @param srcMac Source MAC address
     * @param srcIP Source IP address
     * @param dstMac Destination MAC address
     * @param dstIP Destination IP address
     * @return Ready to send ethernet packet 
     */
    private Packet buildArpPacket (ArpOperation operation, 
            MacAddress srcMac, InetAddress srcIP, MacAddress dstMac, InetAddress dstIP) {
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
            .hardwareType(ArpHardwareType.ETHERNET)
            .protocolType(EtherType.IPV4)
            .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
            .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
            .operation(operation)
            .srcHardwareAddr(srcMac)
            .srcProtocolAddr(srcIP)
            .dstHardwareAddr(dstMac)
            .dstProtocolAddr(dstIP);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
            .dstAddr(dstMac)
            .srcAddr(srcMac)
            .type(EtherType.ARP)
            .payloadBuilder(arpBuilder)
            .paddingAtBuild(true);

        return etherBuilder.build();
    }
}

