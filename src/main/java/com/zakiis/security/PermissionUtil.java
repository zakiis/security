package com.zakiis.security;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.zakiis.security.annotation.Permission;
import com.zakiis.security.exception.NoPermissionException;

public class PermissionUtil {

	/**
	 * check if current user has privileges to this function
	 * @param userRoles roles that current login user has
	 * @param permission perssion that current method need
	 */
	public static void checkFunctionAccess(List<String> userRoles, Permission permission) {
		if (permission == null) {
			throw new NoPermissionException("There is no @Permission on this method.");
		}
		if (permission.bypass()) {
			return;
		}
		if (permission.roles() == null || permission.roles().length == 0) {
			throw new NoPermissionException("No roles can access this method, please contact administrator");
		}
		Set<String> userRoleSet = new HashSet<String>(userRoles);
		if (userRoles == null || userRoles.size() == 0) {
			throw new NoPermissionException("User don't have privilege on this method, please contact administrator.");
		}
		boolean hasPermission = false;
		for (String role : permission.roles()) {
			if (userRoleSet.contains(role)) {
				hasPermission = true;
				break;
			}
		}
		if (!hasPermission) {
			throw new NoPermissionException("User don't have privilege on this method, please contact administrator.");
		}
	}
}
