/*
Computer Security Assignment 4
March 26, 2019
Team Members: Glen Johnson, Lizzy Hamaoka, Logan Vining
*/
package jnetpcap.security.assignment;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.packet.format.FormatUtils;

public class ScannerFinder {

    public static void main(String[] args) throws IOException {
        //Hashmaps to store the number of Syns sent and the number of SynAcks received
        Map<String, Integer> sentSyn = new HashMap<>();
        Map<String, Integer> recSynAck = new HashMap<>();

        // StringBuilder is used to get error messages in case if any error occurs
        StringBuilder errbuf = new StringBuilder();

        // Make the pcap object
        Pcap pcap = Pcap.openOffline(args[0], errbuf);

        //If the pcap file does not exist, throw an error
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        pcap.loop(-1, new JPacketHandler<StringBuilder>() {

            @Override
            public void nextPacket(JPacket packet, StringBuilder errbuff) {
                //Get relevant fields for the packet
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Http http = new Http();

                //Check for both a tcp and ip connection
                if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                    //Convert the source IP bytes to a string
                    String ipAddress = FormatUtils.ip(ip.source());

                    //Check if syn packet
                    //If syn flag is true and ack is false
                    if (tcp.flags_SYN() == true && tcp.flags_ACK() == false){
                        //Check if the ip is already in the hash
                        Integer count = sentSyn.get(ipAddress);
                        //If it doesn't exist, put it into the table with a count of 1 for the current packet
                        if (count == null) {
                            sentSyn.put(ipAddress, 1);
                        }
                        //If it does exist, increment the count by one for the current packet
                        else {
                            sentSyn.put(ipAddress, count + 1);
                        }
                    }

                    //Check if SYN ACK packet
                    //If syn flag and ack flag are true
                    else if (tcp.flags_SYN() == true && tcp.flags_ACK() == true) {
                        //Check if the ip is already in the hash
                        Integer count = recSynAck.get(ipAddress);
                        //If it doesn't exist, put it into the table with a count of 1 for the current packet
                        if (count == null) {
                            recSynAck.put(ipAddress, 1);
                        }
                        //If it does exist, increment the count by one for the current packet
                        else {
                            recSynAck.put(ipAddress, count + 1);
                        }
                    }
                }
            }
        }, errbuf);

        pcap.close();

        BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"));
        
        writer.write("Computer Security Assignment 4\n");
        writer.write("March 26, 2019\n");
        writer.write("Team Members: Glen Johnson, Lizzy Hamaoka, Logan Vining\n");
        writer.write("\n");
        writer.write("\n");
        writer.write("\n");
        
        //Go through each ip in the sentSyn table
        for (String ip : sentSyn.keySet()) {
            //Check if that IP never received a SYN-ACK
            if (recSynAck.get(ip) != null)
            {
                //Check if that IP sent 3 x as many SYN as SYN-ACK
                if (sentSyn.get(ip) >= (3 * recSynAck.get(ip)))
                {
                    writer.write(ip + "\n");
                    System.out.println(ip);
                }
            }
        }
        
        writer.close();
    }
}
