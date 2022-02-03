package com.matic.security.test;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.matic.security.HMACUtil;
import com.matic.security.codec.HexUtil;

public class HMACUtilTest {

	@Test
	public void test() throws UnsupportedEncodingException {
		String encoding = "UTF-8";
		
		byte[] secretBytes = HMACUtil.genSecretKey(HMACUtil.HMACType.HMAC_MD5);
		System.out.println("密钥：" + HexUtil.toHexString(secretBytes));
		String digest = HMACUtil.digestAsHex("Today is a sunny day.\n今天是一个好天气".getBytes(encoding), secretBytes, HMACUtil.HMACType.HMAC_MD5);
		System.out.println(digest);
		
		secretBytes = HMACUtil.genSecretKey(HMACUtil.HMACType.HMAC_SHA1);
		System.out.println("密钥：" + HexUtil.toHexString(secretBytes));
		digest = HMACUtil.digestAsHex("Today is a sunny day.\n今天是一个好天气".getBytes(encoding), secretBytes, HMACUtil.HMACType.HMAC_SHA1);
		System.out.println(digest);
		
		secretBytes = HMACUtil.genSecretKey(HMACUtil.HMACType.HMAC_SHA_512);
		System.out.println("密钥：" + HexUtil.toHexString(secretBytes));
		digest = HMACUtil.digestAsHex("Today is a sunny day.\n今天是一个好天气".getBytes(encoding), secretBytes, HMACUtil.HMACType.HMAC_SHA_512);
		System.out.println(digest);
		
		secretBytes = HMACUtil.genSecretKey(HMACUtil.HMACType.HMAC_SHA3_512);
		System.out.println("密钥：" + HexUtil.toHexString(secretBytes));
		digest = HMACUtil.digestAsHex("Today is a sunny day.\n今天是一个好天气".getBytes(encoding), secretBytes, HMACUtil.HMACType.HMAC_SHA3_512);
		System.out.println(digest);
	}
}
