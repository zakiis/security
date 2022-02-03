package com.matic.security.test;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

import com.matic.security.MD5Util;

public class MD5UtilTest {

	@Test
	public void test() throws UnsupportedEncodingException {
		String encoding = "UTF-8";
		String digest = MD5Util.digestAsHex("Today is a sunny day.\n今天是一个好天气".getBytes(encoding));
		System.out.println(digest);
	}
}
