package com.zakiis.security;

import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.util.ReflectionUtils;

import com.zakiis.security.annotation.Cipher;
import com.zakiis.security.codec.HexUtil;

public class CipherUtil {

	private static byte[] aesSecretKey;
	private static byte[] iv;
	
	private static Set<Class<?>>excludeClazz = new HashSet<Class<?>>();
	
	static {
		excludeClazz.add(byte.class);
		excludeClazz.add(char.class);
		excludeClazz.add(short.class);
		excludeClazz.add(boolean.class);
		excludeClazz.add(int.class);
		excludeClazz.add(long.class);
		excludeClazz.add(float.class);
		excludeClazz.add(double.class);
		excludeClazz.add(Byte.class);
		excludeClazz.add(Character.class);
		excludeClazz.add(Short.class);
		excludeClazz.add(Boolean.class);
		excludeClazz.add(Integer.class);
		excludeClazz.add(Long.class);
		excludeClazz.add(Float.class);
		excludeClazz.add(Double.class);
		excludeClazz.add(BigDecimal.class);
	}
	
	
	public static void init(byte[] aesSescretKey, byte[] iv) {
		CipherUtil.aesSecretKey = aesSescretKey;
		CipherUtil.iv = iv;
	}
	
	public static void encrypt(Object obj) {
		cipher(obj, javax.crypto.Cipher.ENCRYPT_MODE);
	}

	public static void decrypt(Object obj) {
		cipher(obj, javax.crypto.Cipher.DECRYPT_MODE);
	}
	
	private static boolean cipher(Object obj, int cipherMode) {
		if (obj == null || excludeClazz.contains(obj) 
				|| obj.getClass().getCanonicalName().startsWith("java.")
				|| obj.getClass().getCanonicalName().startsWith("javax.")) {
			return false;
		}
		AtomicBoolean hasCiphered = new AtomicBoolean(false);
		ReflectionUtils.doWithFields(obj.getClass(), field -> {
			if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) {
				return;
			}
			ReflectionUtils.makeAccessible(field);
			Object fieldValue = field.get(obj);
			if (fieldValue == null) {
				return;
			}
			if (field.isAnnotationPresent(Cipher.class)) {
				if (javax.crypto.Cipher.ENCRYPT_MODE == cipherMode) {
					String value = HexUtil.toHexString(AESUtil.encrypt(((String)fieldValue).getBytes(), aesSecretKey, iv));
					field.set(obj, value);
				} else if (javax.crypto.Cipher.DECRYPT_MODE == cipherMode) {
					String value = HexUtil.toHexString(AESUtil.decrypt(((String)fieldValue).getBytes(), aesSecretKey, iv));
					field.set(obj, value);
				}
				hasCiphered.set(true);
				return;
			}
			
			if (Collection.class.isAssignableFrom(field.getClass())) {
				Collection<?> collection = (Collection<?>) fieldValue;
				collection.forEach(v -> {
					boolean ciphered = cipher(obj, cipherMode);
					if (ciphered) {
						hasCiphered.set(true);
					}
				});
			} else if (Map.class.isAssignableFrom(field.getClass())) {
				Collection<?> collection = ((Map<?,?>)fieldValue).values();
				collection.forEach(v -> {
					boolean ciphered = cipher(obj, cipherMode);
					if (ciphered) {
						hasCiphered.set(true);
					}
				});
			} else {
				//find annotation recursively
				cipher(fieldValue, cipherMode);
			}
		});
		
		return hasCiphered.get();
	}
	
}
