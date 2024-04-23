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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import com.hierynomus.smbj.testing.TestingUtils.ConsumerWithError;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.smbj.testing.TestingUtils.DEFAULT_AUTHENTICATION_CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
public class DfsIntegrationTest {
    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    @ParameterizedTest(name = "should connect to DFS share")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#dfsConfig")
    public void shouldConnectToDfsShare(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("dfs")) {
                assertThat(share).isInstanceOf(DiskShare.class);
                List<FileIdBothDirectoryInformation> files = share.list("");
                assertThat(files).map(FileIdBothDirectoryInformation::getFileName).contains("public", "user");
            }
        });
    }

    @ParameterizedTest(name = "should list contents of DFS virtual directory")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#dfsConfig")
    public void shouldListDfsVirtualDirectory(SmbConfig c) throws Exception {
        withDir(c, "user", (dir) -> {
            assertThat(dir.list()).map(FileIdBothDirectoryInformation::getFileName).contains(".");
        });
    }

    @ParameterizedTest(name = "should connect to fallback if first link is broken")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#dfsConfig")
    public void shouldConnectToFallbackIfFirstLinkBroken(SmbConfig c) throws Exception {
        withDir(c, "firstfail-public", dir -> {
            assertThat(dir.list()).map(FileIdBothDirectoryInformation::getFileName).contains(".");
        });
    }

    @ParameterizedTest(name = "should have filename for regular directory share when dfs is enabled GH#603")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#dfsConfig")
    public void shouldHaveFilenameForRegularDirectoryShareWhenDfsIsEnabled(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("a_directory");
                try (Directory dir = share.openDirectory("a_directory", EnumSet.of(AccessMask.GENERIC_READ), null,
                        EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ), SMB2CreateDisposition.FILE_OPEN, null)) {

                    assertThat(dir.getPath()).isEqualTo("a_directory");
                    assertThat(dir.getFileName()).isEqualTo("\\\\localhost\\user\\a_directory");
                    assertThat(dir.getUncPath()).isEqualTo("\\\\localhost\\user\\a_directory");
                }
                share.rmdir("a_directory", false);
            }
        });
    }

    private void withDir(SmbConfig c, String name, ConsumerWithError<Directory> f) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("dfs")) {
                assertThat(share).isInstanceOf(DiskShare.class);
                try (Directory dir = share.openDirectory(name, EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    f.accept(dir);
                }
            }
        });
    }
}
