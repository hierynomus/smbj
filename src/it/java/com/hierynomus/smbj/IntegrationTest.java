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

import static com.hierynomus.smbj.testing.TestingUtils.DEFAULT_AUTHENTICATION_CONTEXT;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.Share;
import com.hierynomus.smbj.testcontainers.SambaContainer;

@Testcontainers
public class IntegrationTest {
    @Container
    private static final SambaContainer samba = new SambaContainer.Builder().build();

    @ParameterizedTest(name = "should connect")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldConnect(SmbConfig c) throws Exception {
        samba.withConnectedClient(c, (connection) -> {
            assertThat(connection).extracting("connected", as(InstanceOfAssertFactories.BOOLEAN)).isTrue();
        });
    }

    @ParameterizedTest(name = "should authenticate")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldAuthenticate(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            assertThat(session).extracting("sessionId").isNotNull();
        });
    }

    @ParameterizedTest(name = "should connect to share")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldConnectToShare(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (Share share = session.connectShare("public")) {
                assertThat(share).isInstanceOf(DiskShare.class);
                assertThat(share).extracting("treeId").isNotNull();
                assertThat(share).extracting("connected", as(InstanceOfAssertFactories.BOOLEAN)).isTrue();
            }
        });
    }

    @ParameterizedTest(name = "should list contents of empty share")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldListContentsOfEmptyShare(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                List<FileIdBothDirectoryInformation> items = share.list("");
                assertThat(items).hasSize(2).map(FileIdBothDirectoryInformation::getFileName).contains(".", "..");
            }
        });
    }

    @Test
    public void shouldListContentsOfShareWithNullPath() throws Exception {
        SmbConfig c = SmbConfig.builder().withMultiProtocolNegotiate(true).build();
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                List<FileIdBothDirectoryInformation> items = share.list(null);
                assertThat(items).hasSize(2).map(FileIdBothDirectoryInformation::getFileName).contains(".", "..");
            }
        });
    }

    @ParameterizedTest(name = "should not fail closing connection twice")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotFailClosingConnectionTwice(SmbConfig c) throws Exception {
        samba.withConnectedClient(c, (connection) -> {
            assertDoesNotThrow(() -> connection.close());
            assertDoesNotThrow(() -> connection.close());
        });
    }

}
