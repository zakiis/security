package com.zakiis.security.jwt.algorithm;

import com.zakiis.security.HMACUtil.HMACType;
import com.zakiis.security.jwt.interfaces.DecodedJwt;

public abstract class Algorithm {

	private final String name;
	private final String description;

	public static Algorithm HMAC256(String secret) throws IllegalArgumentException {
		return new HMACAlgorithm("HS256", HMACType.HMAC_SHA_256.getAlgorithm(), secret);
	}
	
	public static Algorithm HMAC384(String secret) throws IllegalArgumentException {
		return new HMACAlgorithm("HS384", HMACType.HMAC_SHA_384.getAlgorithm(), secret);
	}
	
	public static Algorithm HMAC512(String secret) throws IllegalArgumentException {
		return new HMACAlgorithm("HS512", HMACType.HMAC_SHA_512.getAlgorithm(), secret);
	}

	protected Algorithm(String name, String description) {
		this.name = name;
		this.description = description;
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getSigningKeyId() {
		return null;
	}

	public byte[] sign(byte[] headerBytes, byte[] payloadBytes) {
		// default implementation; keep around until sign(byte[]) method is removed
		byte[] contentBytes = new byte[headerBytes.length + 1 + payloadBytes.length];
		System.arraycopy(headerBytes, 0, contentBytes, 0, headerBytes.length);
		contentBytes[headerBytes.length] = (byte) '.';
		System.arraycopy(payloadBytes, 0, contentBytes, headerBytes.length + 1, payloadBytes.length);

		return sign(contentBytes);
	}

	public abstract byte[] sign(byte[] contentBytes);
	
	public abstract void verify(DecodedJwt jwt);

}
