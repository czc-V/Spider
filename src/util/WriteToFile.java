package util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class WriteToFile {
	private static File file;
	
	public static void writeToFile(String s) {
		
		
		file=new File("word.txt");
		
		try {
			FileWriter out=new FileWriter(file,true);
			out.write(s);                      //����Ϣд������ļ�
			out.close();                        //�ر���
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	

}
