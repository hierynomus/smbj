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
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskEntry;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.List;

import static com.hierynomus.smbj.testing.TestingUtils.DEFAULT_AUTHENTICATION_CONTEXT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Testcontainers
public class SMB2DirectoryIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    @ParameterizedTest(name = "should open directory")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldOpenDirectory(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("public")) {
                try (DiskEntry d = share.openDirectory("folder", EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    assertThat(d).isNotNull().isInstanceOf(Directory.class);
                }
            }
        });
    }

    @ParameterizedTest(name = "should check directory exists")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldCheckDirectoryExists(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("im_a_directory");
                try (File src = share.openFile("im_a_file", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)) {
                    src.write(new ArrayByteChunkProvider("Hello World".getBytes(StandardCharsets.UTF_8), 0));
                }

                assertThat(share.folderExists("im_a_directory")).isTrue();
                assertThat(share.folderExists("does_not_exist")).isFalse();
                assertThat(share.folderExists("im_a_file")).isFalse();

                share.rm("im_a_file");
                share.rmdir("im_a_directory", false);
            }
        });
    }

    @ParameterizedTest(name = "should list directory contents")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldListDirectoryContents(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("public")) {
                List<FileIdBothDirectoryInformation> items = share.list("folder");
                assertThat(items).size().isGreaterThan(0);
            }
        });
    }

    @ParameterizedTest(name = "should not fail if 'rmdir' response is DELETE_PENDING for directory")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotFailIfRmdirResponseIsDeletePendingForDirectory(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                Directory newDir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null);
                newDir.close();
                try (Directory d = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    d.deleteOnClose();
                    assertDoesNotThrow(() -> share.rmdir("to_be_removed", false));
                }
            }
        });
    }

    @ParameterizedTest(name = "should not fail if 'folderExists' response is DELETE_PENDING for directory")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotFailIfFolderExistsResponseIsDeletePendingForDirectory(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                Directory newDir = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null);
                newDir.close();
                try (Directory d = share.openDirectory("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    d.deleteOnClose();
                    assertDoesNotThrow(() -> share.folderExists("to_be_removed"));
                }
            }
        });
    }

    @ParameterizedTest(name = "should create Directory and list contents")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#loggedIn")
    public void shouldCreateDirectoryAndListContents(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("testdir");
                List<FileIdBothDirectoryInformation> items = share.list("");
                assertThat(items).map(FileIdBothDirectoryInformation::getFileName).contains("testdir");
                assertThat(share.list("testdir")).hasSize(2).map(FileIdBothDirectoryInformation::getFileName)
                        .contains(".", "..");
                share.rmdir("testdir", true);
            }
        });
    }
}
