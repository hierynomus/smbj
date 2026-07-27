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
        assertThrows(ToBeImplementedException.class, () -> channel.transferTo(0, 1, null));
        assertThrows(ToBeImplementedException.class, () -> channel.transferFrom(null, 0, 1));
        assertThrows(ToBeImplementedException.class, () -> channel.read(ByteBuffer.allocate(1), 0));
        assertThrows(ToBeImplementedException.class, () -> channel.write(ByteBuffer.allocate(1), 0));
        assertThrows(ToBeImplementedException.class, () -> channel.read(new ByteBuffer[0], 0, 0));
        assertThrows(ToBeImplementedException.class, () -> channel.write(new ByteBuffer[0], 0, 0));
    }
}
