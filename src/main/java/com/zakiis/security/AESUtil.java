package com.zakiis.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zakiis.error.ZakiisAlgorithmError;
import com.zakiis.exception.IllegalArgumentException;

/**
 * Advanced Encryption Standard
 * @author 10901
 */
public class AESUtil {
	
	static final String AES = "AES";
	static final String AES_MODE = "AES/CBC/PKCS7Padding";
	/** 根据AES的分组规则，IV必须是128bit */
	static final String IV_SEED = "0000000000000000";
	
	static KeyGenerator kgen;
	
	static {
		Security.addProvider(new BouncyCastleProvider());
		try {
			kgen = KeyGenerator.getInstance(AES);
			kgen.init(128, SecureRandom.getInstance("SHA1PRNG"));	
		} catch (NoSuchAlgorithmException e) {
			throw new ZakiisAlgorithmError("No such algorithm", e);
		}
		
	}

	public static byte[] encrypt(byte[] sourceBytes, byte[] keyBytes) {
		if (keyBytes == null || keyBytes.length != 16) {
			throw new IllegalArgumentException("Key length must be 16");
		}
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES);
		try {
			Cipher cipher = Cipher.getInstance(AES_MODE);
			IvParameterSpec iv = new IvParameterSpec(IV_SEED.getBytes());
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
			byte[] resultByteArr = cipher.doFinal(sourceBytes);
			return resultByteArr;
		} catch (NoSuchAlgorithmException e) {
			throw new ZakiisAlgorithmError("No such algorithm", e);
		} catch (NoSuchPaddingException e) {
			throw new IllegalArgumentException("No such padding", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalArgumentException("Illegal block size", e);
		} catch (BadPaddingException e) {
			throw new IllegalArgumentException("Bad padding", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new ZakiisAlgorithmError("No such algorithm parameter", e);
		}
	}

	public static byte[] decrypt(byte[] encryptedBytes, byte[] keyBytes) {
		if (keyBytes == null || keyBytes.length != 16) {
			throw new IllegalArgumentException("Key length must be 16");
		}
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, AES);
		try {
			Cipher cipher = Cipher.getInstance(AES_MODE);
			IvParameterSpec iv = new IvParameterSpec(IV_SEED.getBytes());
			cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
			byte[] resultByteArr = cipher.doFinal(encryptedBytes);
			return resultByteArr;
		} catch (NoSuchAlgorithmException e) {
			throw new ZakiisAlgorithmError("No such algorithm", e);
		} catch (NoSuchPaddingException e) {
			throw new IllegalArgumentException("No such padding", e);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid key", e);
		} catch (IllegalBlockSizeException e) {
			throw new IllegalArgumentException("Illegal block size", e);
		} catch (BadPaddingException e) {
			throw new IllegalArgumentException("Bad padding", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new ZakiisAlgorithmError("No such algorithm parameter", e);
		}
	}

	public static byte[] genKey() {
		byte[] encodedFormat = kgen.generateKey().getEncoded();
		return encodedFormat;
	}
}