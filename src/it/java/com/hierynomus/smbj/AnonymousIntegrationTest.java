/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.smbj;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.stream.Stream;

import static com.hierynomus.smbj.testing.TestingUtils.config;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Testcontainers
public class AnonymousIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    static Stream<Arguments> connectWith() {
        return Stream.of(
            Arguments.of(SMB2Dialect.SMB_2_1, false, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_0, false, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_0, true, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_0_2, false, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_0_2, true, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_1_1, false, false, AuthenticationContext.anonymous()),
            Arguments.of(SMB2Dialect.SMB_3_1_1, true, false, AuthenticationContext.anonymous()),
            // Arguments.of(SMB2Dialect.SMB_2_1, false, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_0, false, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_0, true, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_0_2, false, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_0_2, true, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_1_1, false, false, AuthenticationContext.guest()),
            Arguments.of(SMB2Dialect.SMB_3_1_1, true, false, AuthenticationContext.guest())
        );
    }

    @ParameterizedTest(name = "Should authenticate using ({0}, {1}, {2}) with {3}")
    @MethodSource("connectWith")
    public void shouldAuthenticate(SMB2Dialect dialect, boolean encrypt, boolean sign,
            AuthenticationContext authContext) throws Exception {
        SmbConfig base = config(dialect, encrypt, sign);
        samba.withConnectedClient(base, (connection) -> {
            try (Session session = connection.authenticate(authContext)) {
                assertNotNull(session.getSessionId());
            }
        });
    }

    @Test
    public void shouldFailConnectingAnonymousWhenSigningRequired() throws Exception {
        SmbConfig config = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_0).withEncryptData(true).withSigningRequired(true).withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider()).build();
        assertThrows(SMB2GuestSigningRequiredException.class, () -> samba.withConnectedClient(config, (connection) -> {
            try (Session session = connection.authenticate(AuthenticationContext.anonymous())) {
                fail("Should not be able to connect");
            }
        }));
    }

    @ParameterizedTest(name = "Should connect to public share using ({0}, {1}, {2}) with {3}")
    @MethodSource("connectWith")
    public void shouldConnectToPublicShare(SMB2Dialect dialect, boolean encrypt, boolean sign,
            AuthenticationContext authContext) throws Exception {
        SmbConfig base = config(dialect, encrypt, sign);
        samba.withConnectedClient(base, (connection) -> {
            try (Session session = connection.authenticate(authContext)) {
                try (Share share = session.connectShare("public")) {
                    assertInstanceOf(DiskShare.class, share);
                    assertTrue(share.isConnected());
                    assertNotNull(share.getTreeConnect().getTreeId());
                }
            }
        });
    }
}
