package com.xyz.janus;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @author yazhouxie
 * 
 */
public class Janus {

	private static final String VERSION = "1.0";
	private static final String HELP_PAGE = "Janus [dex_file] [apk_file] [output_file]";
	/**
	 * @param args
	 */
	public static void main(String[] params) {
		// TODO Auto-generated method stub
		if ((params.length == 0) || ("--help".equals(params[0])) || ("-h".equals(params[0]))) {
            System.out.println(HELP_PAGE);
            return;
        } else if ("--version".equals(params[0])) {
            System.out.println(VERSION);
            return;
        }

        String cmd = params[0];
        try {
            if ("Janus".equalsIgnoreCase(cmd)) {
            	mergeFile(params[1],params[2],params[3]);
                return;
            }else if ("help".equalsIgnoreCase(cmd)) {
                System.out.println(HELP_PAGE);
                return;
            } else if ("version".equals(cmd)) {
                System.out.println(VERSION);
                return;
            } else {
                throw new Exception(
                        "Unsupported command: " + cmd + ". See --help for supported commands");
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
	}
    
	private static final int EODC = 0x06054b50; //找到End of central directory record地址，magic number 0x06054b50
	private static final int CD = 0x02014b50;//central directory起始位置
	private static void mergeFile(String dexFilePath, String zipFilePath, String outputFilePath) {
		File apk_file = new File(zipFilePath);
		File dex_file = new File(dexFilePath);
		File output_file = new File(outputFilePath);
		if(!output_file.exists() || output_file.isDirectory()) {
			try {
				output_file.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			
			byte[] buffer = new byte[1024];
			
			
			//读取dex文件
			FileInputStream fis_dex = new FileInputStream(dex_file);
			ByteArrayOutputStream baos_dex = new ByteArrayOutputStream();
			while(true) {
				int read = fis_dex.read(buffer);
				if(read < 0) {
					break;
				}
				baos_dex.write(buffer, 0, read);
			}
			byte[] dex_file_bytes = baos_dex.toByteArray();
			int dex_file_length = dex_file_bytes.length;
			
			//读取apk文件
			FileInputStream fis_apk = new FileInputStream(apk_file);
			ByteArrayOutputStream baos_apk = new ByteArrayOutputStream();
			while(true) {
				int read = fis_apk.read(buffer);
				if(read < 0) {
					break;
				}
				baos_apk.write(buffer, 0, read);
			}
			byte[] apk_file_bytes = baos_apk.toByteArray();
			//根据magic number 0x06054b50，找到EOCD地址
			int cd_end_addr = findOffsetFromEnd(apk_file_bytes, EODC,apk_file_bytes.length);
			if(cd_end_addr != -1) {					
				System.out.println("Central Directory end : "+cd_end_addr);
			}
			//16-20是Central Directory的起始地址偏移
			byte[] cdBytes = new byte[]{apk_file_bytes[cd_end_addr+16], apk_file_bytes[cd_end_addr+17],apk_file_bytes[cd_end_addr+18],apk_file_bytes[cd_end_addr+19]};
			int cd_start_addr = Util.bytesToInt(cdBytes);
			System.out.println("Central Directory start : "+cd_start_addr);
			
			//修改偏移量
			int real_cd_offset = (cd_start_addr+dex_file_length);
			System.out.println("Real Central Directory start : "+real_cd_offset);
			byte[] real_cd_offset_bytes = Util.intToBytes(real_cd_offset);
			apk_file_bytes[cd_end_addr+16] = real_cd_offset_bytes[0];
			apk_file_bytes[cd_end_addr+17] = real_cd_offset_bytes[1];
			apk_file_bytes[cd_end_addr+18] = real_cd_offset_bytes[2];
			apk_file_bytes[cd_end_addr+19] = real_cd_offset_bytes[3];
			
			//
			int position = cd_start_addr;
			while(position < cd_end_addr) {
				
				int findOffset = findOffsetFromStart(apk_file_bytes, CD,position,cd_end_addr);
				if(findOffset == -1){
					break;
				}			
				
				//42-46是File Header的起始地址偏移
				byte[] bytes = new byte[]{apk_file_bytes[findOffset+42], apk_file_bytes[findOffset+43],apk_file_bytes[findOffset+44],apk_file_bytes[findOffset+45]};
				int file_header_offset = Util.bytesToInt(bytes);
				int real_file_header_offset = (file_header_offset + dex_file_length);
				byte[] real_file_header_offset_bytes = Util.intToBytes(real_file_header_offset);
				apk_file_bytes[findOffset+42] = real_file_header_offset_bytes[0];
				apk_file_bytes[findOffset+43] = real_file_header_offset_bytes[1];
				apk_file_bytes[findOffset+44] = real_file_header_offset_bytes[2];
				apk_file_bytes[findOffset+45] = real_file_header_offset_bytes[3];
				
				position = findOffset+46;
			}
			
			ByteArrayOutputStream baos_output = new ByteArrayOutputStream();
			baos_output.write(dex_file_bytes);
			baos_output.write(apk_file_bytes);
			byte[] output_bytes = baos_output.toByteArray();
			//32~36修改dex文件总长度
			int real_dex_len = output_bytes.length;
			byte[] real_dex_len_bytes = Util.intToBytes(real_dex_len);
			output_bytes[32] = real_dex_len_bytes[0];
			output_bytes[33] = real_dex_len_bytes[1];
			output_bytes[34] = real_dex_len_bytes[2];
			output_bytes[35] = real_dex_len_bytes[3];
			
			//12~32 更新dex头部的sha-1校验
			byte[] sha1_data = new byte[real_dex_len - 32];
			for (int i = 32; i < output_bytes.length; i++) {
				sha1_data[i-32] = output_bytes[i];
			}
			byte[] sha1 = SHA1Util.getSHA1Data(sha1_data);
			for (int i = 0; i < sha1.length; i++) {				
				output_bytes[12+i] = sha1[i];
			}
			
			//Adler32 校验
			byte[] adler32_data = new byte[real_dex_len - 12];
			for (int i = 12; i < output_bytes.length; i++) {
				adler32_data[i-12] = output_bytes[i];
			}
			long calcAdler32 = Adler32Util.calcAdler32(adler32_data);
			byte[] calcAdler32_bytes = Util.intToBytes((int)calcAdler32);
			for (int i = 0; i < calcAdler32_bytes.length; i++) {
				output_bytes[8+i] = calcAdler32_bytes[i];
			}
			
			FileOutputStream fos_output = new FileOutputStream(output_file);
			fos_output.write(output_bytes);
			fos_output.flush();
			
			fis_apk.close();
			fis_dex.close();
			fos_output.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
	}
	
	private static int findOffsetFromStart(byte[] array, int data,int begin,int end) {
		if(begin < 0) {
			begin = 0;
		}
		byte[] datas = Util.intToBytes(data);
		for (int i = begin; i < end; i++) {
			if(array[i] == datas[0]
				&& array[i+1] == datas[1]
				&& array[i+2] == datas[2]
				&& array[i+3] == datas[3]) {
				return i;
			}
		}
		return -1;
	}
	private static int findOffsetFromEnd(byte[] array, int data, int begin) {
		if(begin > array.length - 4) {
			begin = array.length - 4;
		}
		byte[] datas = Util.intToBytes(data);
		for (int i = begin; i >= 0; i--) {
			if(array[i] == datas[0]
				&& array[i+1] == datas[1]
				&& array[i+2] == datas[2]
				&& array[i+3] == datas[3]) {
				return i;
			}
		}
		return -1;
	}
}
