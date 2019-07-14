package util;

import java.util.ArrayList;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import entity.Windows;



public class CaptureUtil extends Thread{
	
	
	
	private static boolean flag=true;
	public static int number=0;
	
	//用于存储错误信息
	private static StringBuilder errbuf = new StringBuilder();
	
	
	//此方法用于获取设备上的网卡设施
	public static ArrayList<PcapIf> CaptureNet(){
		CaptureUtil.flag=false;
		
		// 用于存储搜索到的网卡
		ArrayList<PcapIf> alldevs = new ArrayList<PcapIf>(); 
		
        //取得设备列表
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
        	JOptionPane.showMessageDialog(null,errbuf.toString(),"错误",JOptionPane.ERROR_MESSAGE); 
            return null;
       	}
        return alldevs;
	}
	
	
	//此方法用于选取网卡并捕获包
	public static void CapturePacket(ArrayList<PcapIf> alldevs){
		CaptureUtil.flag=true;
		PcapIf device = alldevs.get(number);
        System.out.printf("\nChoosing '%s' on your behalf:\n", device.getDescription());
        
        //打开选中的设备
        int snaplen = Pcap.DEFAULT_SNAPLEN; // 默认长度为65535
        int flags = Pcap.MODE_PROMISCUOUS;  // 混杂模式,捕获所有类型的包
        int timeout = 5 * 1000;             // 超时时间设为5秒
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
        	JOptionPane.showMessageDialog(null,errbuf.toString(),"错误",JOptionPane.ERROR_MESSAGE);
            return;
        }
        MyPcapPacketHandler<Object> myhandler = new MyPcapPacketHandler<Object>(); 
       
        System.out.println("point:1");
        System.out.println(flag);
        while(CaptureUtil.flag){
        	pcap.loop(1, myhandler, "/njnetpcap"); 
        }
        pcap.close();  
    } 
	
	public void run(){	
		CaptureUtil.CapturePacket(CaptureUtil.CaptureNet());
	}
	
	
	public static void StopCapturePacket(){
		

		CaptureUtil.flag=false;

		

		
		

		/*
		if(!PacketMatch.lists1.isEmpty()&&!PacketMatch.lists2.isEmpty()&&!PacketMatch.lists3.isEmpty()) {
			System.out.println("第一次握手：-------------------------------------------------");
			System.out.println(PacketMatch.lists1.get(0).toString());
			System.out.println("第一次握手：-------------------------------------------------");
			
			System.out.println("第二次握手：-------------------------------------------------");
			System.out.println(PacketMatch.lists2.get(0).toString());
			System.out.println("第二次握手：-------------------------------------------------");
			
			System.out.println("第三次握手：-------------------------------------------------");
			System.out.println(PacketMatch.lists3.get(0).toString());
			System.out.println("第三次握手：-------------------------------------------------");
			
			
		}
		*/
	}
	
	public static void ClearPacket(){
		PacketMatch.numberOfPacket=0;
		PacketMatch.hm.clear();
		Windows.lItems.clear();	
		Windows.textArea_1.setText("");
		PacketMatch.numberOfArp=0;
		PacketMatch.numberOfTcp=0;
		PacketMatch.numberOfUdp=0;
		PacketMatch.numberOfIcmp=0;
		PacketMatch.numberOfWideSpread=0;
	}
}
