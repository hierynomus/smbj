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
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileNotifyAction;
import com.hierynomus.msfscc.directory.FileNotifyInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.protocol.commons.concurrent.Futures;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.io.ArrayByteChunkProvider;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.testcontainers.SambaContainer;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.concurrent.Future;

import static com.hierynomus.mssmb2.SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME;
import static com.hierynomus.mssmb2.SMB2CompletionFilter.FILE_NOTIFY_CHANGE_LAST_WRITE;
import static com.hierynomus.mssmb2.SMB2CompletionFilter.FILE_NOTIFY_CHANGE_SIZE;
import static com.hierynomus.smbj.testing.TestingUtils.DEFAULT_AUTHENTICATION_CONTEXT;
import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@Testcontainers
public class ChangeNotifyIntegrationTest {
    @Container
    private static final SambaContainer samba = SambaContainer.INSTANCE;

    @ParameterizedTest(name = "should watch changes")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldWatchChanges(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("directory");
                try (Directory d = share.openDirectory("directory", EnumSet.of(AccessMask.GENERIC_READ),
                        EnumSet.of(FileAttributes.FILE_ATTRIBUTE_DIRECTORY), SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    Future<SMB2ChangeNotifyResponse> fut = d.watchAsync(EnumSet.of(FILE_NOTIFY_CHANGE_SIZE,
                            FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE), false);
                    try (File f = share.openFile("directory/TestNotify.txt",
                            EnumSet.of(AccessMask.GENERIC_READ, AccessMask.GENERIC_WRITE, AccessMask.DELETE),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), SMB2ShareAccess.ALL,
                            SMB2CreateDisposition.FILE_CREATE, null)) {
                        f.write(new ArrayByteChunkProvider("Testing 123 123".getBytes(StandardCharsets.UTF_8), 0));
                    }

                    assertThat(fut).isDone();
                    SMB2ChangeNotifyResponse resp = fut.get();
                    assertThat(resp.getFileNotifyInfoList()).isNotNull().size().isOne();
                    FileNotifyInformation fni = resp.getFileNotifyInfoList().get(0);
                    assertThat(fni).extracting("action").isEqualTo(FileNotifyAction.FILE_ACTION_ADDED);
                    assertThat(fni).extracting("fileName").isEqualTo("TestNotify.txt");
                }
                share.rmdir("directory", true);
            }
        });
    }

    @ParameterizedTest(name = "should cancel ChangeNotify")
    @MethodSource("com.hierynomus.smbj.testing.TestingUtils#defaultTestingConfig")
    public void shouldCancelChangeNotify(SmbConfig c) throws Exception {
        samba.withAuthenticatedClient(c, DEFAULT_AUTHENTICATION_CONTEXT, (session) -> {
            try (DiskShare share = (DiskShare) session.connectShare("user")) {
                share.mkdir("to_be_watched");
                try (Directory d = share.openDirectory("to_be_watched", EnumSet.of(AccessMask.GENERIC_ALL),
                        null, SMB2ShareAccess.ALL,
                        SMB2CreateDisposition.FILE_OPEN, null)) {
                    d.deleteOnClose();
                    Future<SMB2ChangeNotifyResponse> fut = d.watchAsync(EnumSet.of(FILE_NOTIFY_CHANGE_FILE_NAME), true);
                    fut.cancel(true);
                    SMB2ChangeNotifyResponse resp = assertDoesNotThrow(
                            () -> Futures.get(fut, SMBRuntimeException.Wrapper));
                    assertThat(resp).extracting("fileNotifyInfoList", as(InstanceOfAssertFactories.LIST)).isEmpty();
                }
            }
        });
    }

}
