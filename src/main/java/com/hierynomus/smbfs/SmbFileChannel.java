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

import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.util.concurrent.locks.ReentrantLock;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;

class SmbFileChannel implements SeekableByteChannel {

    private final ReentrantLock lock = new ReentrantLock();

    private final DiskShare share;
    private final File file;

    private long position;
    private volatile boolean closed;

    SmbFileChannel(DiskShare share, File file) {
        this.share = share;
        this.file = file;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        lock.lock();
        try {
            int read = file.read(dst, position);

            if (read >= 0)
                position += read;

            return read;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public long position() throws IOException {
        lock.lock();
        try {
            return position;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public SeekableByteChannel position(long newPosition) throws IOException {
        lock.lock();
        try {
            this.position = newPosition;
        } finally {
            lock.unlock();
        }
        return this;
    }

    @Override
    public long size() throws IOException {
        return file.getLength();
    }

    @Override
    public SeekableByteChannel truncate(long size) {
        file.setLength(size);
        return this;
    }

    @Override
    public boolean isOpen() {
        return !closed;
    }

    @Override
    public void close() throws IOException {
        if (closed)
            return;

        try (DiskShare s = share;
             File f = file) {
            // close the share and file
            closed = true;
        }
    }
}
