package org.secureauth.sarestapi.guid;

import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import java.util.Hashtable;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.secureauth.sarestapi.SAAccess;
import org.secureauth.sarestapi.data.SAConfig;
import org.secureauth.sarestapi.util.SAFactory;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

public class SAAccessUnitTest {

    private WireMockServer wireMockServer;
    private final String X_REQUEST_ID = "X-Request-Id";
    private final String X_SA_EXT_DATE = "X-SA-Ext-Date";
    private final String X_SA_DATE = "X-SA-Date";
    private final String OLD_IDP = "support.deprecated.idp";
    private final Hashtable<String, Object> config = new Hashtable<String, Object>();
    private final SAConfig saConfig = SAConfig.getInstance();
    @Before
    public void setup() {
        this.wireMockServer = new WireMockServer(8090);
        this.wireMockServer.start();
    }

    @After
    public void teardown() {
        this.wireMockServer.stop();
    }

    @Test
    public void given_SAAccessWithNewRequestIDForEachRequest_When_PerformOutOfBandAuthStateful_Then_XRequestIDHeaderIsPresent() {
        // given
        final SAAccess saAccess = this.createSAAccessWithTransactionId( UUID.randomUUID().toString() );
        final String userId = "test-user-1";
        final String factorId = "9a29542309654256a0d71f9e86095f45";
        // when
        saAccess.sendPushToAcceptReqStateful( userId, factorId, "127.0.0.1", "", "" );
        // then
        this.wireMockServer.verify(
                postRequestedFor( urlEqualTo("/Realm01/api/v1/auth" ) )
                .withHeader( X_REQUEST_ID , matching( "\\S{36}" ) )
        );
    }

    private SAAccess createSAAccessWithTransactionId(String transactionId) {
        return SAFactory.newOf(
                "localhost",
                "8090",
                false,
                true,
                "Realm01",
                "971e6dea94f443ee932f0a3447672aea",
                "19d4364f56975fed0f58716b78693922507de3d37fdb8784edba5c29af2416fd",
                transactionId
        );
    }

    // Checks that the header is X-SA-EXT-DATE and the date has .SSS
    @Test
    public void testHeaderForOldIdPSupportOff() {
        // given
        final SAAccess saAccess = this.createSAAccessWithTransactionId( UUID.randomUUID().toString() );
        final String userId = "test-user-1";
        final String factorId = "9a29542309654256a0d71f9e86095f45";
        // when
        saAccess.sendPushToAcceptReqStateful( userId, factorId, "127.0.0.1", "", "" );
        // then
        this.wireMockServer.verify(
                postRequestedFor( urlEqualTo("/Realm01/api/v1/auth" ) )
                        .withHeader( X_SA_EXT_DATE , matching( ".*\\d{2}\\d*:\\d{2}.\\d{3}\\s.*" ) )
        );
    }


    // Checks that the header is X-SA-DATE and the date doesn't have .SSS
    @Test
    public void testHeaderForOldIdPSupportOn() {
        // given
        config.put( OLD_IDP, true );
        saConfig.updateConfig( config );
        final SAAccess saAccess = this.createSAAccessWithTransactionId( UUID.randomUUID().toString() );
        final String userId = "test-user-1";
        final String factorId = "9a29542309654256a0d71f9e86095f45";
        // when
        saAccess.sendPushToAcceptReqStateful( userId, factorId, "127.0.0.1", "", "" );
        // then
        this.wireMockServer.verify(
                postRequestedFor( urlEqualTo("/Realm01/api/v1/auth" ) )
                        .withHeader( X_SA_DATE , matching( ".*\\d{2}\\d*:\\d{2}\\s.*" ) )
        );
    }
}

