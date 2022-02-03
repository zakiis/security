package com.matic.security.test;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.matic.security.codec.Base64Util;

public class Base64UtilTest {

	@Test
	public void testEncode() {
		byte[] source = "Hello, world!".getBytes();
		String base64Str = Base64Util.encode(source);
		assertEquals("SGVsbG8sIHdvcmxkIQ==", base64Str);
	}
	
	@Test
	public void testDecode() {
		String base64Str = "SGVsbG8sIHdvcmxkIQ==";
		byte[] source = Base64Util.decode(base64Str);
		String content = new String(source);
		assertEquals("Hello, world!", content);
	}
}
