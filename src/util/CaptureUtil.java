package util;

import java.util.ArrayList;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import entity.Windows;



public class CaptureUtil extends Thread{
	
	
	
	private static boolean flag=true;
	public static int number=0;
	
	//���ڴ洢������Ϣ
	private static StringBuilder errbuf = new StringBuilder();
	
	
	//�˷������ڻ�ȡ�豸�ϵ�������ʩ
	public static ArrayList<PcapIf> CaptureNet(){
		CaptureUtil.flag=false;
		
		// ���ڴ洢������������
		ArrayList<PcapIf> alldevs = new ArrayList<PcapIf>(); 
		
        //ȡ���豸�б�
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
        	JOptionPane.showMessageDialog(null,errbuf.toString(),"����",JOptionPane.ERROR_MESSAGE); 
            return null;
       	}
        return alldevs;
	}
	
	
	//�˷�������ѡȡ�����������
	public static void CapturePacket(ArrayList<PcapIf> alldevs){
		CaptureUtil.flag=true;
		PcapIf device = alldevs.get(number);
        System.out.printf("\nChoosing '%s' on your behalf:\n", device.getDescription());
        
        //��ѡ�е��豸
        int snaplen = Pcap.DEFAULT_SNAPLEN; // Ĭ�ϳ���Ϊ65535
        int flags = Pcap.MODE_PROMISCUOUS;  // ����ģʽ,�����������͵İ�
        int timeout = 5 * 1000;             // ��ʱʱ����Ϊ5��
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null) {
        	JOptionPane.showMessageDialog(null,errbuf.toString(),"����",JOptionPane.ERROR_MESSAGE);
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
			System.out.println("��һ�����֣�-------------------------------------------------");
			System.out.println(PacketMatch.lists1.get(0).toString());
			System.out.println("��һ�����֣�-------------------------------------------------");
			
			System.out.println("�ڶ������֣�-------------------------------------------------");
			System.out.println(PacketMatch.lists2.get(0).toString());
			System.out.println("�ڶ������֣�-------------------------------------------------");
			
			System.out.println("���������֣�-------------------------------------------------");
			System.out.println(PacketMatch.lists3.get(0).toString());
			System.out.println("���������֣�-------------------------------------------------");
			
			
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
