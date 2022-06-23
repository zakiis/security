package com.zakiis.security.jwt;

import com.zakiis.security.jwt.algorithm.Algorithm;
import com.zakiis.security.jwt.interfaces.DecodedJwt;

/**
 * JSON Web Token
 * https://datatracker.ietf.org/doc/html/rfc7519
 * @author 10901
 */
public class JWTUtil {

	public static JWTCreator.Builder create() {
		return new JWTCreator.Builder();
	}
	
	public static DecodedJwt decode(String token) {
		return new JWTDecoder(token);
	}

	public static JWTVerifier require(Algorithm algorithm) {
		return new JWTVerifier(algorithm);
	}
}
