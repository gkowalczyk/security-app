package com.javappa.securityapp.security.domain;

public enum RoleEnum {

	ROLE_USER("ROLE_USER"), ROLE_ADMIN("ROLE_ADMIN");

	private final String value;

	RoleEnum(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}
}
