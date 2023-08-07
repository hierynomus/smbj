package com.hierynomus.smbj;

import org.junit.jupiter.api.Test;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;

import static org.junit.jupiter.api.Assertions.*;
import static com.hierynomus.smbj.testing.TestingUtils.*;

public class AnonymousIntegrationTest {

    private SmbConfig base = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_1_1).withEncryptData(true).withSigningRequired(false).withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider()).build();

    @Test
    public void shouldAuthenticateAnonymous() throws Exception {
        withConnectedClient(base, (connection) -> {
            try (Session session = connection.authenticate(AuthenticationContext.anonymous())) {
                assertNotNull(session.getSessionId());
            }
        });
    }

    @Test
    public void shouldFailConnectingAnonymousWhenSigningRequired() throws Exception {
        SmbConfig config = SmbConfig.builder(base).withSigningRequired(true).build();
        assertThrows(SMB2GuestSigningRequiredException.class, () -> withConnectedClient(config, (connection) -> {
            try (Session session = connection.authenticate(AuthenticationContext.anonymous())) {
                fail("Should not be able to connect");
            }
        }));
    }

    @Test
    public void shouldConnectToPublicShare() throws Exception {
        withConnectedClient(base, (connection) -> {
            try (Session session = connection.authenticate(AuthenticationContext.anonymous())) {
                try (Share share = session.connectShare("public")) {
                    assertInstanceOf(DiskShare.class, share);
                    assertTrue(share.isConnected());
                    assertNotNull(share.getTreeConnect().getTreeId());
                }
            }
        });
    }
}
