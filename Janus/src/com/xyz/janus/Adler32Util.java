package com.xyz.janus;

import java.util.zip.Adler32;

/**
 * 
 * @author yazhouxie
 *
 */
public class Adler32Util {
	

    public static long calcAdler32(byte[] data) {
        Adler32 checksum = new Adler32();
        checksum.update(data);
        return checksum.getValue();
    }

}
