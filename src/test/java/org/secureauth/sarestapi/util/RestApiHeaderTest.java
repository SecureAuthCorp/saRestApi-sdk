package org.secureauth.sarestapi.util;

import org.apache.hc.client5.http.utils.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.secureauth.sarestapi.data.Requests.StatusRequest;
import org.secureauth.sarestapi.data.SAAuth;
import org.secureauth.sarestapi.queries.StatusQuery;
import org.secureauth.sarestapi.resources.Resource;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static org.junit.jupiter.api.Assertions.*;

class RestApiHeaderTest {

	private final static String realm = "realm1";
	private final static String applicationID = "applicationID";
	private final static String applicationKey = Hex.encodeHexString("applicationKey".getBytes());
	private static SAAuth saAuth;

	@BeforeEach
	public void setup() {
		saAuth = new SAAuth(applicationID,applicationKey,realm);
	}

	// Maybe could change this to check throws DecoderException and Throw the exception instead of logging
	@Test
	void getAuthorizationHeaderWithoutEncodingKey() {
		String query = StatusQuery.queryStatus(saAuth.getRealm(), "userId");
		saAuth.setApplicationKey("applicationKey");

		String header = RestApiHeader.getAuthorizationHeader(saAuth, Resource.METHOD_GET, query, getServerTime());

		assertEquals("Basic YXBwbGljYXRpb25JRDo=", header);
	}

	@Test
	void getAuthorizationHeaderWithoutPayload() {
		String query = StatusQuery.queryStatus(saAuth.getRealm(), "userId");

		String header = RestApiHeader.getAuthorizationHeader(saAuth, Resource.METHOD_GET, query, getServerTime());

		assertTrue(header.startsWith("Basic YXBwbGljYXRpb25"));
		assertTrue(header.length()>30);
	}

	@Test
	void testGetAuthorizationHeaderWithPayload() {
		StatusRequest statusRequest = new StatusRequest("someStatus");

		String query = StatusQuery.queryStatus(saAuth.getRealm(), "userId");

		String header = RestApiHeader.getAuthorizationHeader(saAuth, Resource.METHOD_POST, query, statusRequest, getServerTime());

		assertTrue(header.startsWith("Basic YXBwbGljYXRpb25"));
		assertTrue(header.length()>30);
	}


	private String getServerTime() {
		LocalDateTime fixLocalDateTime = LocalDateTime.of(2020, 6, 12, 0,0);
		DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;
		return formatter.format(fixLocalDateTime);
	}
}