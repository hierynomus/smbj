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
package com.hierynomus.smbj.share;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.messages.SMB2Echo;
import com.hierynomus.mssmb2.messages.SMB2ReadRequest;
import com.hierynomus.mssmb2.messages.SMB2ReadResponse;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smbj.connection.AbortTestConnection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.hierynomus.smbj.connection.AbortTestConnection.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@Timeout(10)
public class FileInputStreamAbortTest {
    @Test
    public void abortFailsPrefetchedReadAndOrdinaryResponseWithinOneSecond() throws Exception {
        try (AbortTestConnection test = new AbortTestConnection()) {
            SMB2Echo ordinary = echo();
            Future<SMB2Packet> ordinaryResponse = test.connection.send(ordinary);
            File file = mock(File.class);
            SMB2ReadResponse initial = new SMB2ReadResponse() {
                @Override
                public byte[] getData() {
                    return new byte[] {7};
                }

                @Override
                public int getDataLength() {
                    return 1;
                }
            };
            when(file.readAsync(0, 1)).thenReturn(CompletableFuture.completedFuture(initial));
            AtomicReference<Future<SMB2ReadResponse>> prefetch = new AtomicReference<>();
            SMB2ReadRequest prefetchedRead = new SMB2ReadRequest(
                SMB2Dialect.SMB_2_1, new SMB2FileId(), 0, 0, 1, 1);
            when(file.readAsync(1, 1)).thenAnswer(invocation -> {
                Future<SMB2ReadResponse> future = test.connection.send(prefetchedRead);
                prefetch.set(future);
                return future;
            });

            try (FileInputStream input = new FileInputStream(file, 1, 30000, null)) {
                assertEquals(7, input.read());
                assertNotNull(prefetch.get());
                FutureTask<TransportException> read = task(() ->
                    assertThrows(TransportException.class, () -> input.read()));
                FutureTask<Throwable> ordinaryWaiter = task(() -> transportFailure(ordinaryResponse));
                test.awaitResponseWaiter(prefetchedRead);
                test.awaitResponseWaiter(ordinary);

                long start = System.nanoTime();
                task(() -> {
                    test.connection.close(true);
                    return null;
                }).get(1, TimeUnit.SECONDS);
                assertNotNull(read.get(1, TimeUnit.SECONDS));
                assertNotNull(ordinaryWaiter.get(1, TimeUnit.SECONDS));
                transportFailure(prefetch.get());
                assertPrompt(start);
                test.assertNoOutstandingRequests();
            }
        }
    }
}
