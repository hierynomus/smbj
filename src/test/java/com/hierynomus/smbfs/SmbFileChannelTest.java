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

import com.hierynomus.smbj.share.File;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SmbFileChannelTest {

    @Mock
    private File file;

    @Test
    void isARealFileChannel() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        assertTrue(channel instanceof FileChannel);
    }

    @Test
    void readsAndAdvancesPosition() throws Exception {
        when(file.read(any(ByteBuffer.class), anyLong())).thenReturn(5L);

        SmbFileChannel channel = new SmbFileChannel(file, 10);
        int read = channel.read(ByteBuffer.allocate(5));

        assertEquals(5, read);
        assertEquals(15, channel.position());
        verify(file).read(any(ByteBuffer.class), org.mockito.ArgumentMatchers.eq(10L));
    }

    @Test
    void writesAndAdvancesPosition() throws Exception {
        when(file.write(any(ByteBuffer.class), anyLong())).thenReturn(5L);

        SmbFileChannel channel = new SmbFileChannel(file, 10);
        int written = channel.write(ByteBuffer.allocate(5));

        assertEquals(5, written);
        assertEquals(15, channel.position());
    }

    @Test
    void closeClosesOnlyTheFileHandle() throws Exception {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        channel.close();

        verify(file).close();
        assertTrue(!channel.isOpen());
    }

    @Test
    void unsupportedOperationsThrowToBeImplemented() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        assertThrows(ToBeImplementedException.class, () -> channel.map(FileChannel.MapMode.READ_ONLY, 0, 1));
        assertThrows(ToBeImplementedException.class, () -> channel.lock(0, 1, false));
        assertThrows(ToBeImplementedException.class, () -> channel.tryLock(0, 1, false));
    }

    @Test
    void positionalReadDoesNotAffectChannelPosition() throws Exception {
        when(file.read(any(ByteBuffer.class), org.mockito.ArgumentMatchers.eq(100L))).thenReturn(5L);

        SmbFileChannel channel = new SmbFileChannel(file, 10);
        int read = channel.read(ByteBuffer.allocate(5), 100);

        assertEquals(5, read);
        assertEquals(10, channel.position());
    }

    @Test
    void positionalWriteDoesNotAffectChannelPosition() throws Exception {
        when(file.write(any(ByteBuffer.class), org.mockito.ArgumentMatchers.eq(100L))).thenReturn(5L);

        SmbFileChannel channel = new SmbFileChannel(file, 10);
        int written = channel.write(ByteBuffer.allocate(5), 100);

        assertEquals(5, written);
        assertEquals(10, channel.position());
    }

    @Test
    void positionalReadRejectsNegativePosition() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        assertThrows(IllegalArgumentException.class, () -> channel.read(ByteBuffer.allocate(1), -1));
    }

    @Test
    void positionalWriteRejectsNegativePosition() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        assertThrows(IllegalArgumentException.class, () -> channel.write(ByteBuffer.allocate(1), -1));
    }

    @Test
    void scatteringReadFillsBuffersInOrderAndStopsOnShortRead() throws Exception {
        // fully drains the first buffer (4 bytes), then only partially fills the second (2 bytes),
        // then reports EOF - the mock must actually advance the buffer position like a real read would,
        // otherwise dst.hasRemaining() would never turn false and the scatter loop would spin forever.
        int[] callCount = {0};
        when(file.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
            ByteBuffer dst = invocation.getArgument(0);
            callCount[0]++;
            int n = callCount[0] == 1 ? 4 : (callCount[0] == 2 ? 2 : -1);
            if (n < 0) {
                return -1L;
            }
            for (int i = 0; i < n; i++) {
                dst.put((byte) i);
            }
            return (long) n;
        });

        SmbFileChannel channel = new SmbFileChannel(file, 0);
        ByteBuffer[] dsts = {ByteBuffer.allocate(4), ByteBuffer.allocate(4)};
        long read = channel.read(dsts, 0, dsts.length);

        assertEquals(6, read);
        assertEquals(6, channel.position());
        assertTrue(!dsts[0].hasRemaining());
        assertEquals(2, dsts[1].position());
    }

    @Test
    void scatteringReadReturnsMinusOneOnImmediateEof() throws Exception {
        when(file.read(any(ByteBuffer.class), anyLong())).thenReturn(-1L);

        SmbFileChannel channel = new SmbFileChannel(file, 0);
        ByteBuffer[] dsts = {ByteBuffer.allocate(4)};
        long read = channel.read(dsts, 0, dsts.length);

        assertEquals(-1, read);
    }

    @Test
    void gatheringWriteWritesAllBuffersInOrder() throws Exception {
        when(file.write(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
            ByteBuffer src = invocation.getArgument(0);
            int n = src.remaining();
            src.position(src.limit());
            return (long) n;
        });

        SmbFileChannel channel = new SmbFileChannel(file, 0);
        ByteBuffer[] srcs = {ByteBuffer.allocate(4), ByteBuffer.allocate(4)};
        long written = channel.write(srcs, 0, srcs.length);

        assertEquals(8, written);
        assertEquals(8, channel.position());
    }

    @Test
    void readIndicesAreValidated() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);
        ByteBuffer[] dsts = {ByteBuffer.allocate(1)};

        assertThrows(IndexOutOfBoundsException.class, () -> channel.read(dsts, 0, 2));
        assertThrows(IndexOutOfBoundsException.class, () -> channel.write(dsts, -1, 1));
    }

    @Test
    void transferToReadsFromPositionAndWritesToTarget() throws Exception {
        when(file.read(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
            ByteBuffer dst = invocation.getArgument(0);
            int n = Math.min(dst.remaining(), 4);
            for (int i = 0; i < n; i++) {
                dst.put((byte) i);
            }
            return n == 0 ? -1L : (long) n;
        });

        SmbFileChannel channel = new SmbFileChannel(file, 0);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        WritableByteChannel target = java.nio.channels.Channels.newChannel(out);

        long transferred = channel.transferTo(0, 10, target);

        assertEquals(10, transferred);
        assertEquals(10, out.toByteArray().length);
    }

    @Test
    void transferFromReadsFromSourceAndWritesAtPosition() throws Exception {
        when(file.write(any(ByteBuffer.class), anyLong())).thenAnswer(invocation -> {
            ByteBuffer src = invocation.getArgument(0);
            int n = src.remaining();
            src.position(src.limit());
            return (long) n;
        });

        byte[] data = new byte[10];
        java.io.ByteArrayInputStream in = new java.io.ByteArrayInputStream(data);
        ReadableByteChannel source = java.nio.channels.Channels.newChannel(in);

        SmbFileChannel channel = new SmbFileChannel(file, 0);
        long transferred = channel.transferFrom(source, 0, 10);

        assertEquals(10, transferred);
    }

    @Test
    void transferToRejectsNegativeArguments() {
        SmbFileChannel channel = new SmbFileChannel(file, 0);

        assertThrows(IllegalArgumentException.class, () -> channel.transferTo(-1, 1, null));
        assertThrows(IllegalArgumentException.class, () -> channel.transferFrom(null, -1, 1));
    }
}
