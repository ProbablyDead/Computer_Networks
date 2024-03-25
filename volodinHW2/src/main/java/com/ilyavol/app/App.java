package com.ilyavol.app;

import java.util.Map;
import java.util.Scanner;

public class App {
    private final static String IP = "10.255.196.224";
    private final static String MAC = "3c:a6:f6:12:86:a1";

    private static PcapARP pcap = null;

    private final static Map<String, Runnable> options = Map.of(
            "1", () -> {
                try { pcap.printAllARPs(); } 
                catch (Exception e) { 
                    System.out.println("No such ip: " + IP); 
                }
            },

            "2", () -> { 
                System.out.print("\nEnter devise IP:\t");
                Scanner in_ = new Scanner(System.in);

                try {
                    String ip = in_.next();
                    String mac = pcap.getMACbyIP(ip); 
                    System.out.println(mac != null ? "For ip: " + ip + "\nFound mac address:\t"+ mac : "No such devise");
                } 
                catch (Exception e) {
                    e.printStackTrace();
                }

                in_.close();
            },

            "3", () -> { 
                System.out.print("\nEnter time (in ms) for you'd like to collect the statistics: \t");

                Scanner in_ = new Scanner(System.in);
                try {
                    pcap.printStatistic(in_.nextLong());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                in_.close();
            },

            "4", () -> {
                try {
                    String result = pcap.getDuplicateIP();

                    System.out.println(result != null ?
                            "Found duplicate ip at mac:\t" + result :
                            "No duplicate ip");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            },
            "5", () -> {
                try {
                    pcap.sendTargetedMessages();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
    );

    public static void main(String args[]) {
        printOptions();

        try {
            pcap = new PcapARP(IP, MAC);
        } catch (Exception e) {
            System.out.println("Check hardcoded IP and MAC");
        }

        Scanner in = new Scanner(System.in);

        System.out.print("Select option number:\t");

        switchOptions(in.next());

        in.close();
    }

    private static void printOptions() {
        String options = "";

        options += "Application options:\n";
        options += "\t1. Print all captured ARP packets\t(use <Ctrl-c> to stop),\n";
        options += "\t2. Get MAC address by IP,\n";
        options += "\t3. Get statistics,\n";
        options += "\t4. Check for the same IP in the network\n";
        options += "\t5. Targeted arp messages\n";

        System.out.println(options);
    }
    
    private static void switchOptions (String option) {
        Runnable exec = options.get(option);
        
        if (exec == null) {
            System.out.println("No such option!");
            return;
        }

        System.out.println("Loading...");

        exec.run();
    }
}
