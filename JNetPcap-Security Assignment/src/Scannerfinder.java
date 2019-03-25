package assignment4;

import java.util.HashMap;
import java.util.Map;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.*;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.packet.format.FormatUtils;

public class ScannerFinder {

    public static void main(String[] args) {

        // StringBuilder is used to get error messages in case if any error occurs
        StringBuilder errbuf = new StringBuilder();

        // Make the pcap object
        Pcap pcap = Pcap.openOffline(args[0], errbuf);

        //If the pcap file does not exist, throw an error
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        Map<String, Integer> sendSyn = new HashMap<String, Integer>();
        Map<String, Integer> synAck = new HashMap<String, Integer>();

        pcap.loop(-1, new JPacketHandler<StringBuilder>() {

            public void nextPacket(JPacket packet, StringBuilder errbuff) {
                //Get relevant fields for the packet
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                Http http = new Http();

                if (packet.hasHeader(ip)) {

                }
            }
        }, errbuf);

        pcap.close();
    }
}
