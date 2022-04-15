package com.zakiis.security.jwt;

import com.zakiis.security.jwt.algorithm.Algorithm;
import com.zakiis.security.jwt.interfaces.DecodedJwt;

/**
 * JSON Web Token
 * https://datatracker.ietf.org/doc/html/rfc7519
 * @author 10901
 */
public class JwtUtil {

	public static JwtCreator.Builder create() {
		return new JwtCreator.Builder();
	}
	
	public static DecodedJwt decode(String token) {
		return new JwtDecoder(token);
	}

	public static JwtVerifier require(Algorithm algorithm) {
		return new JwtVerifier(algorithm);
	}
}
