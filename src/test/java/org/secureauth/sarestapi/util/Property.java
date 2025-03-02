package org.secureauth.sarestapi.util;

public enum Property {
	REALM("idp.realm"),
	API_APPLICATION_ID("idp.realm.api.application.id"),
	API_APPLICATION_KEY("idp.realm.api.application.key"),
	HOST("idp.host"),
	PORT("idp.port"),
	SSL("idp.ssl"),
	VALID_USERNAME("user.username"),
	VALID_PIN("user.pin"),
	VALID_PASSWORD("user.password"),
	USER_DOMAIN("user.domain"),
	VALID_FACTOR_ID_FOR_OATH_OTP("user.oath.totp.factor.id"),
	VALID_OATH_TOTP_SHARED_KEY("user.oath.totp.shared.key"),
	VALID_OATH_TOTP_LENGTH("user.oath.totp.length"),
	VALID_OTP_PIN_CODE("user.otp.pin"),
	VALID_OTP_OATH_CODE("user.otp.oath"),
	VALID_HOST_ADDRESS("valid.host.address"),
	VALID_FINGERPRINT_ID("valid.fingerprint.id"),
	VALID_YUBICO_TOKEN("valid.yubico.token"),
	VALID_IP("user.ip"),
	ASSUME_TEST("assume.test"),
	ASSUME_TEST_TRANSITIVE("assume.test.transitive");

	private final String value;

	private Property(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
