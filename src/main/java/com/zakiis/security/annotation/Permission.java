package com.zakiis.security.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
@Documented
public @interface Permission {
	
	/** roles which can access this method, user only need one of the roles */
	String[] roles() default {};
	
	/** if bypass equals true, this method can be accessed by anyone*/
	boolean bypass() default false;
}
