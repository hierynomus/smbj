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
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.msfscc.fileinformation.FileIdFullDirectoryInformation;
import com.hierynomus.msfscc.fileinformation.FileInternalInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.io.InputStreamByteChunkProvider;
import com.hierynomus.smbj.share.DiskEntry;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import com.hierynomus.smbj.testing.LoggingProgressListener;
import com.hierynomus.smbj.testing.TestingUtils;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.hierynomus.smbj.testing.TestingUtils.DEFAULT_AUTHENTICATION_CONTEXT;
import static com.hierynomus.smbj.testing.TestingUtils.endOfFile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Testcontainers
public class SMB2FileIntegrationTest {

    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    @ParameterizedTest(name = "should open file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldOpenFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("public")) {
                try (DiskEntry f = share.open("test.txt", EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    assertThat(f).isNotNull().isInstanceOf(File.class);
                }
            }
        });
    }

    @ParameterizedTest(name = "should create File 'test.txt'")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldCreateFileAndListContentsOfShare(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File f = share.openFile("test.txt", EnumSet.of(AccessMask.GENERIC_ALL), null, SMB2ShareAccess.ALL,
                        null, null)) {
                    List<FileIdBothDirectoryInformation> items = share.list("");
                    assertThat(items).map(FileIdBothDirectoryInformation::getFileName).contains("test.txt");
                    f.deleteOnClose();
                }
            }
        });
    }

    @ParameterizedTest(name = "should check file exists")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldCheckFileExists(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("im_a_directory");
                try (File src = share.openFile("im_a_file", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OVERWRITE_IF, null)) {
                    src.write(new ArrayByteChunkProvider("Hello World".getBytes(StandardCharsets.UTF_8), 0));
                }

                assertThat(share.fileExists("im_a_file")).isTrue();
                assertThat(share.fileExists("im_a_directory")).isFalse();
                assertThat(share.fileExists("does_not_exist")).isFalse();

                share.rm("im_a_file");
                share.rmdir("im_a_directory", false);
            }
        });
    }

    @ParameterizedTest(name = "should read file contents of file in directory")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldReadFileContentsOfFileInDirectory(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("dirForFile");
                String filePath = "dirForFile\\" + TestingUtils.randomFileName();
                try (File f = share.openFile(filePath, EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0));
                }

                try (File f = share.openFile(filePath, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    try (InputStream is = f.getInputStream()) {
                        byte[] buf = new byte[1024];
                        int read = is.read(buf);
                        assertThat(new String(buf, 0, read, StandardCharsets.UTF_8)).isEqualTo("Hello World!");
                    }
                }

                share.rmdir("dirForFile", true);
            }
        });
    }

    @ParameterizedTest(name = "should not delete locked file until closed")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotDeleteLockedFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File f = share.openFile("locked", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        EnumSet.noneOf(SMB2ShareAccess.class),
                        SMB2CreateDisposition.FILE_CREATE, null)) {
                    SMBApiException ex = assertThrows(SMBApiException.class, () -> share.rm("locked"));
                    assertThat(ex.getStatusCode()).isEqualTo(NtStatus.STATUS_SHARING_VIOLATION.getValue());
                    assertThat(share.list("")).map(FileIdBothDirectoryInformation::getFileName).contains("locked");
                }
                share.rm("locked");
            }
        });
    }

    @ParameterizedTest(name = "should transfer big file to share")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldTransferBigFileToShare(SmbConfig c) throws Exception {
        byte[] bytes = new byte[10 * 1024 * 1024 + 10];
        TestingUtils.RANDOM.nextBytes(bytes);
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                if (share.fileExists("bigfile")) {
                    share.rm("bigfile");
                }
                try (File f = share.openFile("bigfile", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        EnumSet.noneOf(SMB2ShareAccess.class),
                        SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new ArrayByteChunkProvider(bytes, 0));
                }

                try (File f = share.openFile("bigfile", EnumSet.of(AccessMask.GENERIC_READ), null,
                        EnumSet.noneOf(SMB2ShareAccess.class),
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    int offset = 0;
                    byte[] buf = new byte[1024];
                    try (InputStream is = f.getInputStream()) {
                        int read;
                        while ((read = is.read(buf)) != -1) {
                            assertThat(buf).startsWith(Arrays.copyOfRange(bytes, offset, offset + read));
                            offset += read;
                        }
                    }
                }

                share.rm("bigfile");
            }
        });
    }

    @ParameterizedTest(name = "should lock and unlock a file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldLockAndUnlockFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File fileToLock = share.openFile("fileToLock",
                        EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null,
                        EnumSet.noneOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_CREATE, null)) {
                    assertDoesNotThrow(() -> fileToLock.requestLock().exclusiveLock(0, 10, true).send());
                    assertDoesNotThrow(() -> fileToLock.requestLock().unlock(0, 10).send());
                }

                share.rm("fileToLock");
            }
        });
    }

    @ParameterizedTest(name = "should fail to lock overlapping ranges")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldFailToLockOverlappingRange(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File fileToLock = share.openFile("fileToLock",
                        EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE), null,
                        EnumSet.noneOf(SMB2ShareAccess.class), SMB2CreateDisposition.FILE_CREATE, null)) {
                    assertDoesNotThrow(() -> fileToLock.requestLock().exclusiveLock(0, 10, true).send());
                    assertThrows(SMBApiException.class,
                            () -> fileToLock.requestLock().exclusiveLock(5, 15, true).send());
                    assertDoesNotThrow(() -> fileToLock.requestLock().unlock(0, 10).send());
                    assertDoesNotThrow(() -> fileToLock.requestLock().exclusiveLock(5, 15, true).send());
                    assertDoesNotThrow(() -> fileToLock.requestLock().unlock(5, 15).send());
                }
                share.rm("fileToLock");
            }
        });
    }

    @ParameterizedTest(name = "should be able to read fileID from FileIdBothDirectoryInformation")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldReadFileIDFromFileIdBothDirectoryInformation(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("public")) {
                List<FileIdBothDirectoryInformation> infoList = share.list("folder");
                assertThat(infoList).isNotEmpty();
                FileIdBothDirectoryInformation first = infoList.stream().filter((i) -> !i.getFileName().startsWith("."))
                        .findFirst().orElseThrow();
                try (DiskEntry f = share.open("folder\\" + first.getFileName(), EnumSet.of(AccessMask.GENERIC_READ),
                        null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    FileInternalInformation fif = f.getFileInformation(FileInternalInformation.class);
                    assertThat(first.getFileId()).isEqualTo(fif.getIndexNumber());
                }
            }
        });
    }

    @ParameterizedTest(name = "should be able to read fileID from FileIdFullDirectoryInformation")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldReadFileIDFromFileIdFullDirectoryInformation(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("public")) {
                List<FileIdFullDirectoryInformation> infoList = share.list("folder",
                        FileIdFullDirectoryInformation.class);
                assertThat(infoList).isNotEmpty();
                FileIdFullDirectoryInformation first = infoList.stream().filter((i) -> !i.getFileName().startsWith("."))
                        .findFirst().orElseThrow();
                try (DiskEntry f = share.open("folder\\" + first.getFileName(), EnumSet.of(AccessMask.GENERIC_READ),
                        null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    FileInternalInformation fif = f.getFileInformation(FileInternalInformation.class);
                    assertThat(first.getFileId()).isEqualTo(fif.getIndexNumber());
                }
            }
        });
    }

    @ParameterizedTest(name = "should append to a file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldAppendToFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File f = share.openFile("append.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    try (OutputStream os = f.getOutputStream(new LoggingProgressListener())) {
                        os.write("Hello World!".getBytes(StandardCharsets.UTF_8));
                    }
                }

                assertThat(share.fileExists("append.txt")).isTrue();

                try (File f = share.openFile("append.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    try (OutputStream os = f.getOutputStream(new LoggingProgressListener(), true)) {
                        os.write("\nGoodbye World!".getBytes(StandardCharsets.UTF_8));
                    }
                }

                try (File f = share.openFile("append.txt", EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    try (InputStream is = f.getInputStream()) {
                        byte[] buf = new byte[1024];
                        int read = is.read(buf);
                        assertThat(new String(buf, 0, read, StandardCharsets.UTF_8))
                                .isEqualTo("Hello World!\nGoodbye World!");
                    }
                }

                share.rm("append.txt");
            }
        });
    }

    @ParameterizedTest(name = "should copy files remotely")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldCopyFilesRemotely(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File f = share.openFile("srcfile.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0));
                }

                try (File src = share.openFile("srcfile.txt", EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    try (File dst = share.openFile("dstfile.txt", EnumSet.of(AccessMask.FILE_WRITE_DATA), null,
                            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                        src.remoteCopyTo(dst);

                        assertThat(share.fileExists("dstfile.txt")).isTrue();

                        assertThat(endOfFile(src)).isEqualTo(endOfFile(dst));
                    }
                }

                share.rm("srcfile.txt");
                share.rm("dstfile.txt");
            }
        });
    }

    @ParameterizedTest(name = "should not fail if 'rm' response is DELETE_PENDING for file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotFileIfRmResponseIsDeletePendingForFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File newFile = share.openFile("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    newFile.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0));
                }
                try (File f = share.openFile("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    f.deleteOnClose();

                    assertDoesNotThrow(() -> share.rm("to_be_removed"));
                }
            }
        });
    }

    @ParameterizedTest(name = "should not fail if 'fileExists' response is DELETE_PENDING for file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldNotFileIfFileExistsResponseIsDeletePendingForFile(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File newFile = share.openFile("to_be_removed", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    newFile.write(new ArrayByteChunkProvider("Hello World!".getBytes(StandardCharsets.UTF_8), 0));
                }
                try (File f = share.openFile("to_be_removed", EnumSet.of(AccessMask.GENERIC_ALL), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    f.deleteOnClose();

                    assertDoesNotThrow(() -> share.fileExists("to_be_removed"));
                }
            }
        });
    }

    @ParameterizedTest(name = "should write async file")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldWriteAsyncFile(SmbConfig c) throws Exception {
        byte[] bytes = new byte[2 * 1024 * 1024 + 10];
        TestingUtils.RANDOM.nextBytes(bytes);
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, session -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                Future<Long> fut = null;
                try (File f = share.openFile("bigfile", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OVERWRITE_IF, null)) {
                    fut = f.writeAsync(new InputStreamByteChunkProvider(new ByteArrayInputStream(bytes)));
                }

                assertThat(fut).succeedsWithin(5, TimeUnit.SECONDS, InstanceOfAssertFactories.LONG)
                        .isEqualTo(bytes.length);

                try (File f = share.openFile("bigfile", EnumSet.of(AccessMask.GENERIC_READ), null,
                        EnumSet.noneOf(SMB2ShareAccess.class),
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    int offset = 0;
                    byte[] buf = new byte[1024];
                    try (InputStream is = f.getInputStream()) {
                        int read;
                        while ((read = is.read(buf)) != -1) {
                            assertThat(buf).startsWith(Arrays.copyOfRange(bytes, offset, offset + read));
                            offset += read;
                        }
                    }
                }

                share.rm("bigfile");
            }
        });
    }

    @ParameterizedTest(name = "should transfer file using GZipOutputStream via InputStreamByteChunkProvider to SMB Share")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldTransferAndUnzipFileInOneGo(SmbConfig c) throws Exception {
        java.io.File dataFile = java.io.File.createTempFile("datafile", "txt");
        try (FileWriter fw = new FileWriter(dataFile)) {
            for (int i = 0; i < 10000; i++) {
                fw.write("Hello World!\n");
            }
        }

        java.io.File zipFile = java.io.File.createTempFile("datafile", "txt.gz");
        try (InputStream is = new java.io.FileInputStream(dataFile);
                OutputStream os = new java.io.FileOutputStream(zipFile)) {
            try (GZIPOutputStream gos = new GZIPOutputStream(os)) {
                IOUtils.copy(is, gos);
            }
        }

        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                try (File f = share.openFile("datafile.txt.gz", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new InputStreamByteChunkProvider(new java.io.FileInputStream(zipFile)));
                }
                try (File f = share.openFile("datafile.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new InputStreamByteChunkProvider(new java.io.FileInputStream(dataFile)));
                }
                try (File f = share.openFile("unzipped.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                    f.write(new InputStreamByteChunkProvider(
                            new GZIPInputStream(new java.io.FileInputStream(zipFile))));
                }

                assertThat(share.fileExists("datafile.txt.gz")).isTrue();
                assertThat(share.fileExists("datafile.txt")).isTrue();
                assertThat(share.fileExists("unzipped.txt")).isTrue();

                try (File orig = share.openFile("datafile.txt", EnumSet.of(AccessMask.GENERIC_READ), null,
                        SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                    try (File unzipped = share.openFile("unzipped.txt", EnumSet.of(AccessMask.GENERIC_READ), null,
                            SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
                        assertThat(endOfFile(orig)).isEqualTo(endOfFile(unzipped));
                    }
                }

                share.rm("datafile.txt.gz");
                share.rm("datafile.txt");
                share.rm("unzipped.txt");
            }
        });

        dataFile.delete();
        zipFile.delete();
    }
}
