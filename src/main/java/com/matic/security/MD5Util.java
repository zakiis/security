package com.matic.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.matic.error.MaticAlgorithmError;
import com.matic.security.codec.HexUtil;

/**
 * Message Digest Algorithm
 * @author 10901
 */
public class MD5Util {

	static final String MD5 = "MD5";
	
	public static byte[] digest(byte[] sourceBytes) {
		try {
			MessageDigest md = MessageDigest.getInstance(MD5);
			md.update(sourceBytes);
			byte[] result = md.digest();
			return result;
		} catch (NoSuchAlgorithmException e) {
			throw new MaticAlgorithmError("No such algorithm", e);
		}
	}
	
	public static String digestAsHex(byte[] sourceBytes) {
		byte[] digest = digest(sourceBytes);
		String result = HexUtil.toHexString(digest);
		return result;
	}
}
