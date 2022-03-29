package com.zakiis.security;

import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
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
		if (obj == null) {
			return;
		}
		if (obj instanceof Collection) {
			Collection<?> collection = (Collection<?>) obj;
			collection.forEach(v -> cipher(v, javax.crypto.Cipher.ENCRYPT_MODE));
		} else if (obj instanceof Map) {
			Collection<?> collection = ((Map<?, ?>) obj).values();
			collection.forEach(v -> cipher(v, javax.crypto.Cipher.ENCRYPT_MODE));
		} else {
			cipher(obj, javax.crypto.Cipher.ENCRYPT_MODE);
		}
	}

	public static void decrypt(Object obj) {
		if (obj == null) {
			return;
		}
		if (obj instanceof Collection) {
			Collection<?> collection = (Collection<?>) obj;
			collection.forEach(v -> cipher(v, javax.crypto.Cipher.DECRYPT_MODE));
		} else if (obj instanceof Map) {
			Collection<?> collection = ((Map<?, ?>) obj).values();
			collection.forEach(v -> cipher(v, javax.crypto.Cipher.DECRYPT_MODE));
		} else {
			cipher(obj, javax.crypto.Cipher.DECRYPT_MODE);
		}
	}
	
	private static boolean cipher(Object obj, int cipherMode) {
		AtomicBoolean noCipherField = new AtomicBoolean(true);
		if (obj == null) {
			noCipherField.set(false);
			return noCipherField.get();
		}
		if (needExcludeClazz(obj.getClass())) {
			return noCipherField.get();
		}
		
		ReflectionUtils.doWithFields(obj.getClass(), field -> {
			if (Modifier.isStatic(field.getModifiers()) || Modifier.isTransient(field.getModifiers())) {
				return;
			}
			ReflectionUtils.makeAccessible(field);
			Object fieldValue = field.get(obj);
			if (fieldValue == null) {
				// can't determine whether it has cipher field or not if the value is null
				if (!needExcludeClazz(field.getType())) {
					noCipherField.set(false);
				}
				return;
			}
			if (field.isAnnotationPresent(Cipher.class)) {
				if (javax.crypto.Cipher.ENCRYPT_MODE == cipherMode) {
					String value = getEncryptedValue((String)fieldValue);
					field.set(obj, value);
				} else if (javax.crypto.Cipher.DECRYPT_MODE == cipherMode) {
					String value = getDecryptedValue((String)fieldValue);
					field.set(obj, value);
				}
				noCipherField.set(false);
				return;
			}
			
			if (Collection.class.isAssignableFrom(field.getClass())) {
				Collection<?> collection = (Collection<?>) fieldValue;
				collection.forEach(v -> {
					boolean childNoCipherField = cipher(obj, cipherMode);
					if (!childNoCipherField) {
						noCipherField.set(false);
					}
				});
			} else if (Map.class.isAssignableFrom(field.getClass())) {
				Collection<?> collection = ((Map<?,?>)fieldValue).values();
				collection.forEach(v -> {
					boolean childNoCipherField = cipher(obj, cipherMode);
					if (!childNoCipherField) {
						noCipherField.set(false);
					}
				});
			} else {
				if (needExcludeClazz(obj.getClass())) {
					return;
				}
				//find annotation recursively
				boolean childNoCipherField = cipher(fieldValue, cipherMode);
				if (!childNoCipherField) {
					noCipherField.set(false);
				}
			}
		});
		if (noCipherField.get()) {
			excludeClazz.add(obj.getClass());
		}
		return noCipherField.get();
	}
	
	private static boolean needExcludeClazz(Class<?> clazz) {
		if (excludeClazz.contains(clazz) 
				|| clazz.getCanonicalName().startsWith("java.")
				|| clazz.getCanonicalName().startsWith("javax.")) {
			return true;
		}
		return false;
	}
	
	public static String getEncryptedValue(String str) {
		return HexUtil.toHexString(AESUtil.encrypt(str.getBytes(), aesSecretKey, iv));
	}
	
	public static String getDecryptedValue(String str) {
		if (isEncryptedValue(str)) {
			return new String(AESUtil.decrypt(HexUtil.toByteArray(str), aesSecretKey, iv));
		} else {
			return str;
		}
	}
	
	final static Pattern hexPattern = Pattern.compile("^[a-fA-F0-9]+$");
	private static boolean isEncryptedValue(String str) {
		if (StringUtils.isEmpty(str) || str.length() % 16 != 0
				|| !hexPattern.matcher(str).find()) {
			return false;
		}
		return true;
	}
}
