package com.xyz.janus;

import java.security.MessageDigest;

/**
 * 
 * @author yazhouxie
 *
 */
public class SHA1Util {
	
    public static byte[] getSHA1Data(byte[] data) {  
        if (data == null) {  
            return null;  
        }  
        try {  
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");  
            messageDigest.update(data);  
            return messageDigest.digest();  
        } catch (Exception e) {  
            throw new RuntimeException(e);  
        }  
    } 
}
