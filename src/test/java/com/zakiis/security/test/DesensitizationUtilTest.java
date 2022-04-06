package com.zakiis.security.test;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.zakiis.security.logging.DesensitizationUtil;

public class DesensitizationUtilTest {

	@Test
	public void test() {
		String content = "{\"userName\":\"zhangsan123\", \"password\":\"123456\", \"mobile\":\"13112341234\", \"sex\":\"male\", \"country\":\"China\", \"age\":65}";
		
		Set<String> replaceFields = new HashSet<String>();
		replaceFields.add("userName");
		replaceFields.add("mobile");
		replaceFields.add("email");
		Set<String> eraseFields = new HashSet<String>();
		eraseFields.add("age");
		eraseFields.add("password");
		Set<String> dropFields = new HashSet<String>();
		dropFields.add("sex");
		DesensitizationUtil.init(replaceFields, eraseFields, dropFields);
		
		String msg = DesensitizationUtil.convert(content);
		System.out.println(msg);
		content = "{userName=zhangsan123, age = , password=123456, mobile = 13112341234, sex=male, country=China}";
		System.out.println(DesensitizationUtil.convert(content));
		
		content = "add user start, param: {\"userName\":\"zhangsan123\", \"password\":\"123456\", \"mobile\":\"13112341234\", \"sex\":\"male\", \"country\":\"China\", \"age\":65}";
		System.out.println(DesensitizationUtil.convert(content));
		
		content = "add user start, params: {userName=zhangsan123, email=test-123-hello@qq.com, age = , password=123456, mobile = 13112341234, sex=male, country=China}";
		System.out.println(DesensitizationUtil.convert(content));
	}
}
