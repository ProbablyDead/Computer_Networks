package com.ilyavol.app;

import org.pcap4j.core.*;

import java.io.EOFException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

import java.util.Map;
import java.util.Scanner;

public class App {
    private final static String IP = "10.255.197.37";
    private final static String MAC = "3c:a6:f6:12:86:a1";

    private static void printOptions() {
        String options = "";

        options += "Application options:\n";
        options += "\t1. Print all captured ARP packets\t(use <Ctrl-c> to stop),\n";
        options += "\t2. Get MAC address by IP,\n";
        options += "\t3. Get statistics,\n";
        options += "\t4. Check for the same IP in the network\n";

        System.out.println(options);
    }
    private final static PcapARP pcap = new PcapARP(IP, MAC);

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

                try {pcap.printMACbyIP(in_.next()); } 
                catch (Exception e) {
                    System.out.println("Error");
                }

                in_.close();
            },

            "3", () -> { 
                System.out.print("\nEnter time (in ms) for you'd like to collect the statistics: \t");

                Scanner in_ = new Scanner(System.in);
                try {
                    pcap.printStatistic(in_.nextLong());
                } catch (Exception e) {
                    System.out.println("Error");
                }
                in_.close();
            },

            "4", () -> { }
            );

    private static void switchOptions (String option) {
        Runnable exec = options.get(option);
        
        if (exec == null) {
            System.out.println("No such option!");
            return;
        }

        System.out.println("Loading...");

        exec.run();
    }
    
    public static void main(String args[]) 
            throws UnknownHostException, PcapNativeException, 
           EOFException, TimeoutException, NotOpenException {
        printOptions();

        Scanner in = new Scanner(System.in);

        System.out.print("Select option number:\t");

        switchOptions(in.next());

        in.close();
    }
}
