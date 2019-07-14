package util;



import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.voip.Rtp;


import entity.Windows;

//
public class PacketMatch {
	public static HashMap hm=new HashMap();
	public static int numberOfPacket=0;
	 private static PacketMatch pm;  
	    private Icmp icmp = new Icmp();  
	    private Tcp tcp = new Tcp();  
	    private Udp udp = new Udp();  
	    private Arp arp= new Arp();
	    private Http http=new Http();
	    private Rtp rtp=new Rtp();
	    
	    private static Ip4 ip4=new Ip4();
	    public static double totalOfDns=0;
	    public static double totalOfRtp=0;
	    public static double totalOfHttp=0;
	    public static double totalOfIcmp=0;
	    public static double totalOfTcp=0;
	    public static double totalOfUdp=0;
	    public static double totalOfArp=0;
	    public static double totalOfSpread=0;
	    public static double totalOfIp=0;
	    public static int numberOfWideSpread=0;
	    public static int numberOfUdp=0;
	    public static int numberOfTcp=0;
	    public static int numberOfIcmp=0;
	    public static int numberOfArp=0;
	    public static int numberOfHttp=0;
	    public static int numberOfDns=0;
	    public static int numberOfRtp=0;
	    
	    
	    
	    //本机Mac地址
		private final static String MAC="144F8AE4221C";
		
		//上传和下载数据量
		public static int Upload=0;
		public static int load=0;
		public static double totalOfUpload=0;
		public static double totalOfLoad=0;
		
		
		//保存三次握手信息
		public  static List<Tcp> lists1=new ArrayList<>();
		public  static List<Tcp> lists2=new ArrayList<>();
		public  static List<Tcp> lists3=new ArrayList<>();
		
		public static Tcp newTcp1;
		public static Tcp newTcp2;
		public static Tcp newTcp3;
		
		
	    
	    
	    //单例
	    public static PacketMatch getInstance() {  
	        if (pm == null) {  
	            pm = new PacketMatch();  
	        }  
	        return pm;  
	    }

		public void handlePacket(PcapPacket packet) {
			Sum(packet);
			handleIp4(packet);
			
			
			if(Windows.FLAG==0) {
				if (packet.hasHeader(icmp)) {  
					handleIcmp(packet);  
					
				}  
				if (packet.hasHeader(arp)) {  
		            handleArp(packet); 
		            
		        }  
		        if (packet.hasHeader(tcp)) {  
		            handleTcp(packet); 
		           
		        }  
		        if (packet.hasHeader(udp)) {  
		            handleUdp(packet); 
		            
		        }
		        //广播数据包的捕获
				if (packet.hasHeader(ip4)) { 
					handleIp4(packet);  
				}
			}else if(Windows.FLAG==1) {
				if (packet.hasHeader(tcp)) {  
					handleTcp(packet);  	
				}
			}else if(Windows.FLAG==2) {
				if (packet.hasHeader(udp)) {  
		            handleUdp(packet); 
		        }
			}else if(Windows.FLAG==3) {
				if (packet.hasHeader(icmp)) {  
					handleIcmp(packet);  
				}  
			}else if(Windows.FLAG==5) {
				if(packet.hasHeader(http)) {
					handleHttp(packet);
				}
			}else if(Windows.FLAG==6) {
				if(packet.hasHeader(tcp)||packet.hasHeader(udp)) {
					handleTcp(packet);
					handleUdp(packet);
				}
				
			}else if(Windows.FLAG==7) {
				if(packet.hasHeader(rtp)) {
					handleRtp(packet);
				}
			}
			else{
				if(packet.hasHeader(arp)) {
					handleArp(packet); 
				}
		         
			}
			//以下四个包都已可以正确捕获
			
	        //广播数据包的捕获
				
				/*以下为实验IP地址的获取
	            packet.getHeader(ip4);
	            System.out.println(ip4.toString());
	            byte[] destinations=new byte[4];
	            ip4.destinationToByteArray(destinations);
	            byte[] sources=new byte[4];
	            		ip4.sourceToByteArray(sources);
	            System.out.println("ip4 destination:"+destinations);
	            System.out.println("ip4 resource:"+sources);
	            System.out.println("ip4 destination:"+ip4.destinationToInt());
	            System.out.println("ip4 resource:"+ip4.sourceToInt());
	            
	            System.out.println("ip4 destination:"+PacketMatch.intToIp(ip4.destinationToInt()));
	            System.out.println("ip4 resource:"+PacketMatch.intToIp(ip4.sourceToInt()));
	            */
		}

		private void handleIp4(PcapPacket packet) {
			
			PacketMatch.totalOfIp=packet.getTotalSize()/(1024.0*1024.0);
			//System.out.println("PacketMatch.totalOfIp:"+PacketMatch.totalOfIp);
			
			packet.getHeader(ip4);
			
			
			
			if(PacketMatch.intToIp(ip4.destinationToInt()).equals("255.255.255.255")){
				//这是一个广播数据包
				System.out.println("收到一个广播数据包");
				Windows.lItems.add(numberOfPacket, "广播数据包");
				hm.put(numberOfPacket, ip4.toString());
				
				numberOfWideSpread++;
				totalOfSpread+=ip4.getLength()/1024.0;
				numberOfPacket++;
			}
		}

		//捕获RTP
		private void handleRtp(PcapPacket packet) {
			packet.getHeader(rtp);
			System.out.println(rtp.toString());
			
			hm.put(numberOfPacket,rtp.toString());
			Windows.lItems.add(numberOfPacket, "RTP");
			totalOfRtp+=rtp.getLength()/1024.0;
			numberOfRtp++;
			numberOfPacket++;
		}
		
		
		//捕获HTTP
		private void handleHttp(PcapPacket packet) {
			
			packet.getHeader(http);
			System.out.println(http.toString());
			hm.put(numberOfPacket, http.toString());
			Windows.lItems.add(numberOfPacket, "HTTP");
			numberOfHttp++;
			totalOfHttp+=http.getLength()/1024.0;
			numberOfPacket++;
			
			
			

		}
		
		private void handleUdp(PcapPacket packet) {
		
			packet.getHeader(udp); 
			System.out.println(udp.toString());
			hm.put(numberOfPacket, udp.toString());
			
			String s;
			//判断是否使用DNS服务
            if(udp.source()==53||udp.destination()==53) {
				Windows.lItems.add(numberOfPacket, "UDP(DNS服务)");
				totalOfDns=udp.getLength()/1024.0;
				numberOfDns++;
				s=String.valueOf(udp.source())+","+String.valueOf(udp.destination())+",UDP(DNS))";
			}else {
				Windows.lItems.add(numberOfPacket, "UDP");
				s=String.valueOf(udp.source())+","+String.valueOf(udp.destination())+",UDP)";
			}
			
			numberOfUdp++;
			totalOfUdp+=udp.getLength()/1024.0;
			numberOfPacket++;
			
			
			write(s);
		}

		private void handleTcp(PcapPacket packet) {
			
			
			//写入文件
			
			packet.getHeader(tcp);  
            System.out.println(tcp.toString());
            hm.put(numberOfPacket, tcp.toString());
            

            //判断三次握手
            if(tcp.flags_SYN()&&!tcp.flags_ACK()) {
 
            	//第一次握手
            	newTcp1=tcp;
            	System.out.println("第一次握手：-------------------------------------------------");
    			System.out.println(PacketMatch.newTcp1.toString());
    			System.out.println("第一次握手：-------------------------------------------------");

            	
            }else if(tcp.flags_SYN()&&tcp.flags_ACK()) {

            	
            	if(tcp.ack()==(newTcp1.seq()+1)) {
            		newTcp2=tcp;
            		System.out.println("第二次握手：-------------------------------------------------");
        			System.out.println(PacketMatch.newTcp2.toString());
        			System.out.println("第二次握手：-------------------------------------------------");
        			
            	}
            	/*
            	
            	for(int i=0;i<lists1.size();i++) {
            		System.out.println("遍历第一次握手列表");
            		System.out.println(lists1.get(i).seq());
            		System.out.println(tcp.ack());
            		if(tcp.ack()==(lists1.get(i).seq()+1)) {
            			System.out.println("添加第二次握手");
            			
            			lists2.add(tcp);
            		}
            	}
            	
            	*/
            }else if(!tcp.flags_SYN()&&tcp.flags_ACK()) {
            	
            	
            	if(newTcp2!=null&&tcp.ack()==(newTcp2.seq()+1)&&tcp.seq()==newTcp2.ack()) {
            		newTcp3=tcp;
            		System.out.println("第三次握手：-------------------------------------------------");
        			System.out.println(PacketMatch.newTcp3.toString());
        			System.out.println("第三次握手：-------------------------------------------------");
            	}
            	/*
            	
            	System.out.println("第三次握手");
            	//第三次握手
            	for(int i=0;i<lists2.size();i++) {
            		if((tcp.ack()==(lists2.get(i).seq()+1))&&(tcp.seq()==lists2.get(i).ack())) {
            			lists3.add(tcp);
            		}
            	}
            	
            	*/
            	
            }
            String s;
            //判断是否使用DNS服务
            if(tcp.source()==53||tcp.destination()==53) {
				Windows.lItems.add(numberOfPacket, "TCP(DNS服务)");
				totalOfDns+=tcp.getLength()/1024.0;
				numberOfDns++;
				s=String.valueOf(tcp.source())+","+String.valueOf(tcp.destination())+",TCP(DNS))";
			}else {
				Windows.lItems.add(numberOfPacket, "TCP");
				s=String.valueOf(tcp.source())+","+String.valueOf(tcp.destination())+",TCP)";
			}
            
            numberOfTcp++;
            totalOfTcp+=tcp.getLength()/1024.0;
            numberOfPacket++;
            
            
			write(s);
            
		}

		private void handleIcmp(PcapPacket packet) {
						
			packet.getHeader(icmp); 
			System.out.println("icmp:"+icmp.toString());
			hm.put(numberOfPacket, icmp.toString());
			Windows.lItems.add(numberOfPacket, "ICMP");
			numberOfIcmp++;
			totalOfIcmp+=icmp.getLength()/1024.0;
			numberOfPacket++;
			
			String s="      ,      ,Icmp)";
			write(s);
		}

		private void handleArp(PcapPacket packet) {
			
			
			packet.getHeader(arp);
			System.out.println("arp:"+arp.toString());
			hm.put(numberOfPacket, arp.toString());
			Windows.lItems.add(numberOfPacket, "ARP");
			numberOfArp++;
			totalOfArp+=arp.getLength()/1024.0;
			numberOfPacket++;
			
			
			String s="      ,      ,Arp)";
			write(s);
		}  
		
		
		//以下函数将Int类型转化为Ip地址
		public static String intToIp(int ipInt){
			return new StringBuilder().append(((ipInt>>24)&0xff)).append('.').append
					((ipInt>>16)&0xff).append('.').append
					((ipInt>>8)&0xff).append('.').append
					((ipInt&0xff)).toString();
		}
		
		
		//计算上行和下行数据量
		private void Sum(PcapPacket newPacket) {
			Ethernet eth=new Ethernet();
			String sourceMac="";
			String destinationMac="";
			if(newPacket.hasHeader(eth)) {
				sourceMac=DatatypeConverter.printHexBinary(eth.source());
				destinationMac=DatatypeConverter.printHexBinary(eth.destination());
				System.out.println(sourceMac);
				System.out.println(destinationMac);
				
				//判断数据包是上行还是下行
				if(MAC.equals(sourceMac)) {
					//是上行数据
					Upload++;
					totalOfUpload+=newPacket.getTotalSize()/1024.0;
					
					System.out.println(newPacket.getTotalSize());
					System.out.println(totalOfUpload);
				}
				if(MAC.equals(destinationMac)) {
					//是下行数据
					load++;
					totalOfLoad+=newPacket.getTotalSize()/1024.0;
				}
			}
			
		}
		
		
		//五元组形式写入文件
		private void write(String s) {
			try {
				System.out.println(ip4);
				System.out.println(InetAddress.getByAddress(ip4.source()).getHostAddress());
				String shuzu="("+InetAddress.getByAddress(ip4.source()).getHostAddress()+","+
						InetAddress.getByAddress(ip4.destination()).getHostAddress()+","+
						s+"\n";
			
				WriteToFile.writeToFile(shuzu);
			} catch (UnknownHostException e) {
				//    
				e.printStackTrace();
			}
		}
}
