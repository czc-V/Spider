package entity;
import java.awt.Color;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JToolBar;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.xml.bind.DatatypeConverter;

import org.jnetpcap.PcapIf;

import util.CaptureUtil;
import util.MyPcapPacketHandler;
import util.PacketMatch;



//���ƴ���
//�����������ʹ��Unicode���ʾ��ʹ�������ʵ�ֿ����ԡ���ƽ̨���ı�ת��������


public class Windows extends JFrame {
	
	private static int i=0;
	
	//���˱�־λ
	private final static int ALL=0;
	private final static int TCP=1;
	private final static int UDP=2;
	private final static int ICMP=3;
	private final static int ARP=4;
	private final static int HTTP=5;
	private final static int DNS=6;
	private final static int RTP=7;
	
	public static int FLAG=ALL;

	private JPanel contentPane;
	private final Action action = new SwingAction();
	private final Action action_1 = new SwingAction_1();
	private final Action action_2 = new SwingAction_2();
	private final Action action_3 = new SwingAction_3();
	private final Action action_4 = new SwingAction_4();
	
	//�����������б���������
	public static DefaultListModel lItems=new DefaultListModel();   
	private  JList list = new JList(lItems);
	private JScrollPane jsp1=new JScrollPane(list);
	
	
	private JTextArea textArea = new JTextArea();
	private JScrollPane jsp2=new JScrollPane(textArea);
	public static JTextArea textArea_1 = new JTextArea();
	
	
	//�����ȡ����ʱ��
	private static double startTime;
	private static double endTime;
	public static double usedTime;
	
	
	public static void main(String[] args) {
		
		/*
		 * Java��GUI���ǵ��̣߳�Ӧ��ʹ���¼������߳�ȥִ�У�û��ʹ����������Ļ����������������
		 * ��С�ĳ������������󲻻ᷢ�������Ӧ�ó����вŻ������������
		 */
		
		//EventQueue�¼����У���װ���첽�¼�ָ�ɻ���
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Windows frame = new Windows();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	
	//�����ʼ��
	public Windows() {
		setTitle("\u6293\u5305");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		//������ǰ��λ����λ�ã��������͸�
		setBounds(100, 100, 692, 500);
		contentPane = new JPanel();
		
		//��contentPane�ڲ��߿�Ϊ�գ�������5�����صĺ��
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		//���þ��Բ���
		contentPane.setLayout(null);
		
		//���ô˴����Ƿ�����û�������С
		this.setResizable(false);
		
		
		JToolBar toolBar = new JToolBar();
		toolBar.setBounds(5, 5, 666, 23);
		contentPane.add(toolBar);
		
		
		JButton button = new JButton("\u8bf7\u9009\u62E9\u7F51\u5361");
		toolBar.add(button);
		
		//�����б������ѡ����������
		final JComboBox comboBox = new JComboBox();
		comboBox.setAction(action);
		
		//��ȡ������Ϣ��ӵ������б���
		ArrayList<PcapIf> alldevs=CaptureUtil.CaptureNet();
		for (PcapIf device : alldevs) {
			String s;
			try {
				s = DatatypeConverter.printHexBinary(device.getHardwareAddress());
				comboBox.addItem(s);
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
        }
		
		comboBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String net=(String)comboBox.getSelectedItem();
				ArrayList<PcapIf> alldevs=CaptureUtil.CaptureNet();
				int i=0;
				System.out.println(net);
				for (PcapIf device : alldevs) {
					try {
						if(net.equals(DatatypeConverter.printHexBinary(device.getHardwareAddress()))){
							CaptureUtil.number=i;
							System.out.println(CaptureUtil.number+":"+device.getDescription());
							CaptureUtil.StopCapturePacket();
						}
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					i++;
		        }
			}
		});
		
		/*
		comboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent arg0) {
			}
		});
		*/
		
		
		toolBar.add(comboBox);
		
		//�����б������ѡ��������ݱ���ʽ
		final JComboBox comboBox1=new JComboBox();
		comboBox1.setAction(action_4);
		comboBox1.addItem("All");
		comboBox1.addItem("TCP");
		comboBox1.addItem("UDP");
		comboBox1.addItem("ICMP");
		comboBox1.addItem("ARP");
		comboBox1.addItem("HTTP");
		comboBox1.addItem("DNS");
		comboBox1.addItem("RTP");
		comboBox1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String item=(String)comboBox1.getSelectedItem();
				System.out.println(item+" clicked");
				if(item.equals("TCP")) {
					FLAG=TCP;
				}else if(item.equals("UDP")) {
					FLAG=UDP;
				}else if(item.equals("ICMP")) {
					FLAG=ICMP;
				}else if(item.equals("ARP")) {
					FLAG=ARP;
				}else if(item.contentEquals("HTTP")){
					FLAG=HTTP;
				}else if(item.contentEquals("DNS")) {
					FLAG=DNS;
				}else if(item.equals("RTP")) {
					FLAG=RTP;
				}
			}
		});
		
		toolBar.add(comboBox1);
		
		
		//��ʼץ��
		JButton button_1 = new JButton("\u5F00\u59CB\u6293\u5305");
		button_1.setAction(action_1);
		toolBar.add(button_1);
		
		//ֹͣץ��
		JButton button_2 = new JButton("\u505c\u6b62\u6293\u5305");
		button_2.setAction(action_2);
		
		/*
		button_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
			}
		});
		*/
		
		toolBar.add(button_2);
		
		//��ռ�¼
		JButton button_3 = new JButton("\u6E05\u7A7A\u8BB0\u5F55");
		button_3.setAction(action_3);
		toolBar.add(button_3);
		
		//���û�ɫ�߿򣬱߿���ɫΪ��
		Border brd=BorderFactory.createMatteBorder(1, 1, 2, 2, Color.black);
		list.setBorder(brd);
		list.addListSelectionListener(new ListSelectionListener(){
			public void valueChanged(ListSelectionEvent arg0) {
				textArea.setText("");
				textArea.append((String)PacketMatch.hm.get(list.getSelectedIndex()));
				
				//�������ڼ��
				//System.out.println(list.getSelectedIndex());
				//System.out.println((String)PacketMatch.hm.get(list.getSelectedIndex()));
				//System.out.println("point:1");
				
			}
		});
		
		
		jsp1.setBounds(5, 28, 258, 343);
		contentPane.add(jsp1);
		jsp2.setBounds(263, 28, 408, 343);
		contentPane.add(jsp2);
		textArea_1.setBounds(5, 371, 666, 100);
		contentPane.add(textArea_1);
		
		
		
	}
	
	private class SwingAction extends AbstractAction {
		
		public SwingAction() {
			putValue(NAME, "ѡ������");
			putValue(SHORT_DESCRIPTION, "\u9009\u62e9\u7f51\u5361");
		}
		public void actionPerformed(ActionEvent e) {
			
			if(i==0) {
				
				ArrayList<PcapIf> alldevs=CaptureUtil.CaptureNet();
				if(alldevs!=null){
			        System.out.println("Network devices has been found:");
			        int i = 1;
			        for (PcapIf device : alldevs) {
			            try {
							System.out.println("��"+(i++)+"����������:"+device.getName()+"\n��Ϣ:"+DatatypeConverter.printHexBinary(device
							        .getHardwareAddress()));
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
			            
			        }
				}
				i++;
			}
			
		}
	}
	private class SwingAction_1 extends AbstractAction {
		public SwingAction_1() {
			putValue(NAME, "��ʼץ��");
			putValue(SHORT_DESCRIPTION, "\u5F00\u59CB\u6293\u5305");
		}
		public void actionPerformed(ActionEvent e) {
			//ץ���߳�
			startTime=System.currentTimeMillis();
			(new CaptureUtil()).start();
		}
	}
	private class SwingAction_2 extends AbstractAction {
		public SwingAction_2() {
			putValue(NAME, "ֹͣץ��");
			putValue(SHORT_DESCRIPTION, "\u505c\u6b62\u6293\u5305");
		}
		public void actionPerformed(ActionEvent e) {
			CaptureUtil.StopCapturePacket();
			endTime=System.currentTimeMillis();
			usedTime=(endTime-startTime)/1000;
			textArea_1.setText("");
			String message="Tcp:"+PacketMatch.numberOfTcp+"��  "+PacketMatch.totalOfTcp+"KB "+"   "+
							"Udp:"+PacketMatch.numberOfUdp+"��  "+PacketMatch.totalOfUdp+"KB "+"   "+
							"Icmp:"+PacketMatch.numberOfIcmp+"��  "+PacketMatch.totalOfIcmp+"KB "+"   "+
							"Arp:"+PacketMatch.numberOfArp+"��  "+PacketMatch.totalOfArp+"KB "+"\n"+
							"�㲥���ݰ�"+PacketMatch.numberOfWideSpread+"��"+"  "+PacketMatch.totalOfSpread+" KB"+"   "+
							"HTTP:"+PacketMatch.numberOfHttp+"�� "+PacketMatch.totalOfHttp+"KB"+"   "+
							"DNS:"+PacketMatch.numberOfDns+"�� "+PacketMatch.totalOfDns+"KB"+"   "+
							"RTP:"+PacketMatch.numberOfRtp+"�� "+PacketMatch.totalOfRtp+"KB"+"\n"+
							"�ϴ����ݰ���"+PacketMatch.Upload+"��"+" "+PacketMatch.totalOfUpload+" KB"+"   "+
							"�������ݰ���"+PacketMatch.load+"��"+" "+PacketMatch.totalOfLoad+" KB"+"\n"+
							"��������"+PacketMatch.totalOfIp+"MB"+"    "+
							"��ʱ��"+usedTime;
			textArea_1.append(message);
		}
	}
	private class SwingAction_3 extends AbstractAction {
		public SwingAction_3() {
			putValue(NAME, "��ռ�¼");
			putValue(SHORT_DESCRIPTION, "\u6E05\u7A7A\u8BB0\u5F55");
		}
		public void actionPerformed(ActionEvent e) {
			CaptureUtil.ClearPacket();
		}
	}
	
	private class SwingAction_4 extends AbstractAction{
		public SwingAction_4() {
			putValue(SHORT_DESCRIPTION,"\u8bf7\u9009\u62e9\u8fc7\u6ee4\u7c7b\u578b");
		}
		public void actionPerformed(ActionEvent e) {
			
		}
	}
}

