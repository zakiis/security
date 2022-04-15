package com.zakiis.security.test;

import java.util.Calendar;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.zakiis.security.jwt.JwtUtil;
import com.zakiis.security.jwt.algorithm.Algorithm;
import com.zakiis.security.jwt.exception.JWTVerificationException;
import com.zakiis.security.jwt.interfaces.DecodedJwt;
import com.zakiis.security.test.model.User;

public class JwtUtilTest {
	
	Logger log = LoggerFactory.getLogger(JwtUtilTest.class);

	@Test
	public void testCreate() {
		User user = new User();
		user.setId(123L);
		user.setPassword("zs23APassx");
		Calendar issueAt = Calendar.getInstance();
		Calendar expireAt = Calendar.getInstance();
		expireAt.add(Calendar.MINUTE, 30);
		String token = JwtUtil.create()
			.withSubject(String.valueOf(user.getId()))
			.withIssuedAt(issueAt.getTime())
			.withExpiresAt(expireAt.getTime())
			.withClaim("age", "25")
			.sign(Algorithm.HMAC256(user.getPassword()));
		System.out.println(token);
	}
	
	@Test
	public void testVerify() {
		String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOiIyMDIyLTA0LTE1IDA5OjQwOjAyIiwiaWF0IjoiMjAyMi0wNC0xNSAwOToxMDowMiIsImFnZSI6IjI1In0.7nADXMM2AjB5XMOiuXtxsEJholZNj9n_DhKinDrjzDc";
		DecodedJwt decodedJwt = JwtUtil.decode(token);
		User user = getUser(Long.valueOf(decodedJwt.getSubject()));
		try {
			JwtUtil.require(Algorithm.HMAC256(user.getPassword())).verify(decodedJwt);
		} catch (JWTVerificationException e) {
			log.error("jwt token not valid, user id:{}, reason:{}", decodedJwt.getSubject(), e.getMessage());
		}
	}
	
	private User getUser(Long userId) {
		User user = new User();
		user.setId(123L);
		user.setPassword("zs23APassx");
		if (userId == 123L) {
			return user;
		}
		return null;
	}
}
