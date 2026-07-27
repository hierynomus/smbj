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
package com.hierynomus.smbfs;

import com.hierynomus.msfscc.FileNotifyAction;
import com.hierynomus.msfscc.directory.FileNotifyInformation;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.WatchEvent;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmbWatchKeyTest {

    @Mock
    private DiskShare diskShare;

    @Mock
    private SmbFileSystem fileSystem;

    @Mock
    private Directory directory;

    @Captor
    private ArgumentCaptor<String> pathCaptor;

    private SmbWatchService watchService;
    private SmbPath watchedPath;

    @BeforeEach
    void setUp() {
        when(diskShare.isConnected()).thenReturn(true);
        watchService = new SmbWatchService(diskShare, fileSystem);
        watchedPath = SmbPath.of(fileSystem, null, Collections.singletonList("some\\dir"));
    }

    private Future<SMB2ChangeNotifyResponse> respondWith(FileNotifyAction action, String fileName) {
        FileNotifyInformation info = new FileNotifyInformation() {
            @Override
            public FileNotifyAction getAction() {
                return action;
            }

            @Override
            public String getFileName() {
                return fileName;
            }
        };

        SMB2ChangeNotifyResponse response = mock(SMB2ChangeNotifyResponse.class);
        when(response.getFileNotifyInfoList()).thenReturn(List.of(info));
        return CompletableFuture.completedFuture(response);
    }

    @Test
    void watchesTheActualRegisteredPathNotAHardcodedName() {
        when(diskShare.openDirectory(pathCaptor.capture(), anySet(), any(), anySet(), any(), any()))
            .thenReturn(directory);
        when(directory.watchAsync(anySet(), anyBoolean())).thenReturn(new CompletableFuture<>());

        watchService.register(watchedPath);

        assertEquals(watchedPath.toString(), pathCaptor.getValue());
    }

    @Test
    void pollEventsReturnsAndClearsHarvestedEvents() {
        Future<SMB2ChangeNotifyResponse> notifyFuture = respondWith(FileNotifyAction.FILE_ACTION_ADDED, "new.txt");

        when(diskShare.openDirectory(any(), anySet(), any(), anySet(), any(), any())).thenReturn(directory);
        when(directory.watchAsync(anySet(), anyBoolean())).thenReturn(notifyFuture);

        SmbWatchKey key = (SmbWatchKey) watchService.register(watchedPath);

        assertTrue(key.isValid());
        assertTrue(key.isReady());

        List<WatchEvent<?>> events = key.pollEvents();
        assertEquals(1, events.size());
        assertEquals(java.nio.file.StandardWatchEventKinds.ENTRY_CREATE, events.get(0).kind());

        // pollEvents() drains the queue - a second call must not return the same events again
        assertTrue(key.pollEvents().isEmpty());
    }

    @Test
    void resetReArmsAndCancelInvalidatesTheKey() {
        Future<SMB2ChangeNotifyResponse> firstNotify = respondWith(FileNotifyAction.FILE_ACTION_MODIFIED, "a.txt");
        Future<SMB2ChangeNotifyResponse> secondNotify = new CompletableFuture<>();

        when(diskShare.openDirectory(any(), anySet(), any(), anySet(), any(), any())).thenReturn(directory);
        when(directory.watchAsync(anySet(), anyBoolean()))
            .thenReturn(firstNotify)
            .thenReturn(secondNotify);

        SmbWatchKey key = (SmbWatchKey) watchService.register(watchedPath);

        assertTrue(key.isReady());
        key.pollEvents();

        assertTrue(key.reset());
        assertTrue(key.isValid());
        verify(directory, times(2)).watchAsync(anySet(), anyBoolean());

        key.cancel();
        assertFalse(key.isValid());
        assertFalse(key.reset());
    }
}
