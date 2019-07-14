package util;


import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;




//获取数据包
//调用PacketMatch进行处理
public class MyPcapPacketHandler<Object> implements PcapPacketHandler<Object> {
	
	
	
	private Ethernet eth=new Ethernet();
	private Ip4 ip4=new Ip4();
	
	@Override
	public void nextPacket(PcapPacket packet, Object arg1) {
		System.out.println("point:2");
		
		if(packet.hasHeader(new Ip6())) {
			
		}else {
			//数据包大小
			int i=packet.getPacketWirelen();
			System.out.println("Packet Length:"+i);
			int a=packet.getTotalSize();
			System.out.println("Packet Size:"+a);
			
			//完整数据包
			//System.out.println("----------------------------------------Frame----------------------------------------");
			//System.out.println(packet);
			//System.out.println("----------------------------------------Frame----------------------------------------");
			
			
			
			//以太网数据帧
			//packet.getHeader(eth);
			//System.out.println("-----------------------------------------Eth----------------------------------------");
			//System.out.println(eth.toString());
			//System.out.println("-----------------------------------------Eth----------------------------------------");
			
			
			
			
			//获取IP数据包的来源IP和目的IP
			packet.getHeader(ip4);
			try {
				System.out.println("Source:"+InetAddress.getByAddress(ip4.source()).getHostAddress());
				System.out.println("Destination:"+InetAddress.getByAddress(ip4.destination()).getHostAddress());
			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
			
			
			
			
			System.out.println("----------------------------------------Packet----------------------------------------");
			PacketMatch packetMatch = PacketMatch.getInstance();  
	        packetMatch.handlePacket(packet);  
	        System.out.println("------------------------------------------"+PacketMatch.numberOfPacket+"------------------------------------------");
	        System.out.println("");
		}
	
	}

}

