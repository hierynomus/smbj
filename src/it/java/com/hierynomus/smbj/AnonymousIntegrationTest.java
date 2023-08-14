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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.security.bc.BCSecurityProvider;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;

import static org.junit.jupiter.api.Assertions.*;

import java.util.stream.Stream;

import static com.hierynomus.smbj.testing.TestingUtils.*;

public class AnonymousIntegrationTest {

    private SmbConfig base = SmbConfig.builder().withDialects(SMB2Dialect.SMB_3_0).withEncryptData(true).withSigningRequired(false).withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider()).build();

    static Stream<Arguments> connectWith() {
        return Stream.of(
            Arguments.of(config(SMB2Dialect.SMB_2_1, false, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_0, false, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_0, true, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_0_2, false, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_0_2, true, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_1_1, false, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_3_1_1, true, false), AuthenticationContext.anonymous()),
            Arguments.of(config(SMB2Dialect.SMB_2_1, false, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_0, false, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_0, true, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_0_2, false, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_0_2, true, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_1_1, false, false), AuthenticationContext.guest()),
            Arguments.of(config(SMB2Dialect.SMB_3_1_1, true, false), AuthenticationContext.guest())
        );
    }

    private static SmbConfig config(SMB2Dialect dialect, boolean encrypt, boolean signing) {
        return SmbConfig.builder().withDialects(dialect).withEncryptData(encrypt).withSigningRequired(signing).withMultiProtocolNegotiate(true).withDfsEnabled(true).withSecurityProvider(new BCSecurityProvider()).build();
    }

    @ParameterizedTest
    @MethodSource("connectWith")
    public void shouldAuthenticate(SmbConfig base, AuthenticationContext authContext) throws Exception {
        withConnectedClient(base, (connection) -> {
            try (Session session = connection.authenticate(authContext)) {
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

    @ParameterizedTest
    @MethodSource("connectWith")
    public void shouldConnectToPublicShare(SmbConfig base, AuthenticationContext authContext) throws Exception {
        withConnectedClient(base, (connection) -> {
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
