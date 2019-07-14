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



//控制窗口
//本程序的文字使用Unicode码表示，使计算机能实现跨语言、跨平台的文本转换及处理


public class Windows extends JFrame {
	
	private static int i=0;
	
	//过滤标志位
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
	
	//创建并设置列表数据类型
	public static DefaultListModel lItems=new DefaultListModel();   
	private  JList list = new JList(lItems);
	private JScrollPane jsp1=new JScrollPane(list);
	
	
	private JTextArea textArea = new JTextArea();
	private JScrollPane jsp2=new JScrollPane(textArea);
	public static JTextArea textArea_1 = new JTextArea();
	
	
	//计算读取数据时间
	private static double startTime;
	private static double endTime;
	public static double usedTime;
	
	
	public static void main(String[] args) {
		
		/*
		 * Java的GUI都是单线程，应该使用事件调度线程去执行，没有使用这个方法的话，可能造成死锁。
		 * 在小的程序中这种现象不会发生，大的应用程序中才会出现这种现象
		 */
		
		//EventQueue事件队列，封装了异步事件指派机制
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

	
	//窗体初始化
	public Windows() {
		setTitle("\u6293\u5305");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		//参数，前两位坐标位置，后两项宽和高
		setBounds(100, 100, 692, 500);
		contentPane = new JPanel();
		
		//让contentPane内部边框为空，并且有5个像素的厚度
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		
		//采用绝对布局
		contentPane.setLayout(null);
		
		//设置此窗体是否可由用户调整大小
		this.setResizable(false);
		
		
		JToolBar toolBar = new JToolBar();
		toolBar.setBounds(5, 5, 666, 23);
		contentPane.add(toolBar);
		
		
		JButton button = new JButton("\u8bf7\u9009\u62E9\u7F51\u5361");
		toolBar.add(button);
		
		//下拉列表组件，选择网卡类型
		final JComboBox comboBox = new JComboBox();
		comboBox.setAction(action);
		
		//获取网卡信息添加到下拉列表中
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
		
		//下拉列表组件，选择过滤数据报格式
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
		
		
		//开始抓包
		JButton button_1 = new JButton("\u5F00\u59CB\u6293\u5305");
		button_1.setAction(action_1);
		toolBar.add(button_1);
		
		//停止抓包
		JButton button_2 = new JButton("\u505c\u6b62\u6293\u5305");
		button_2.setAction(action_2);
		
		/*
		button_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
			}
		});
		*/
		
		toolBar.add(button_2);
		
		//清空记录
		JButton button_3 = new JButton("\u6E05\u7A7A\u8BB0\u5F55");
		button_3.setAction(action_3);
		toolBar.add(button_3);
		
		//设置花色边框，边框颜色为黑
		Border brd=BorderFactory.createMatteBorder(1, 1, 2, 2, Color.black);
		list.setBorder(brd);
		list.addListSelectionListener(new ListSelectionListener(){
			public void valueChanged(ListSelectionEvent arg0) {
				textArea.setText("");
				textArea.append((String)PacketMatch.hm.get(list.getSelectedIndex()));
				
				//以下用于检测
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
			putValue(NAME, "选择网卡");
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
							System.out.println("第"+(i++)+"个网卡名字:"+device.getName()+"\n信息:"+DatatypeConverter.printHexBinary(device
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
			putValue(NAME, "开始抓包");
			putValue(SHORT_DESCRIPTION, "\u5F00\u59CB\u6293\u5305");
		}
		public void actionPerformed(ActionEvent e) {
			//抓包线程
			startTime=System.currentTimeMillis();
			(new CaptureUtil()).start();
		}
	}
	private class SwingAction_2 extends AbstractAction {
		public SwingAction_2() {
			putValue(NAME, "停止抓包");
			putValue(SHORT_DESCRIPTION, "\u505c\u6b62\u6293\u5305");
		}
		public void actionPerformed(ActionEvent e) {
			CaptureUtil.StopCapturePacket();
			endTime=System.currentTimeMillis();
			usedTime=(endTime-startTime)/1000;
			textArea_1.setText("");
			String message="Tcp:"+PacketMatch.numberOfTcp+"包  "+PacketMatch.totalOfTcp+"KB "+"   "+
							"Udp:"+PacketMatch.numberOfUdp+"包  "+PacketMatch.totalOfUdp+"KB "+"   "+
							"Icmp:"+PacketMatch.numberOfIcmp+"包  "+PacketMatch.totalOfIcmp+"KB "+"   "+
							"Arp:"+PacketMatch.numberOfArp+"包  "+PacketMatch.totalOfArp+"KB "+"\n"+
							"广播数据包"+PacketMatch.numberOfWideSpread+"包"+"  "+PacketMatch.totalOfSpread+" KB"+"   "+
							"HTTP:"+PacketMatch.numberOfHttp+"包 "+PacketMatch.totalOfHttp+"KB"+"   "+
							"DNS:"+PacketMatch.numberOfDns+"包 "+PacketMatch.totalOfDns+"KB"+"   "+
							"RTP:"+PacketMatch.numberOfRtp+"包 "+PacketMatch.totalOfRtp+"KB"+"\n"+
							"上传数据包："+PacketMatch.Upload+"包"+" "+PacketMatch.totalOfUpload+" KB"+"   "+
							"下载数据包："+PacketMatch.load+"包"+" "+PacketMatch.totalOfLoad+" KB"+"\n"+
							"总流量："+PacketMatch.totalOfIp+"MB"+"    "+
							"用时："+usedTime;
			textArea_1.append(message);
		}
	}
	private class SwingAction_3 extends AbstractAction {
		public SwingAction_3() {
			putValue(NAME, "清空记录");
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

