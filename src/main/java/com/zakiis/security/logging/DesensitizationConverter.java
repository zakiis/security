package com.zakiis.security.logging;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

public class DesensitizationConverter extends MessageConverter {

	@Override
	public String convert(ILoggingEvent event) {
		String msg = super.convert(event);
		return DesensitizationUtil.convert(msg);
	}

}
