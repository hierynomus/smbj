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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.concurrent.locks.ReentrantLock;

import static com.hierynomus.smbfs.ToBeImplementedException.toBeImplemented;

/**
 * A {@link FileChannel} backed by an SMB {@link File}. Extending {@code FileChannel}
 * (rather than just implementing {@link java.nio.channels.SeekableByteChannel}) makes
 * instances usable wherever a real {@code FileChannel} is expected, e.g. via
 * {@code Files.newByteChannel(...) instanceof FileChannel}. The positional/scatter-gather
 * operations that have no reasonable SMB equivalent (yet) throw {@link ToBeImplementedException}.
 */
class SmbFileChannel extends FileChannel {

    private final ReentrantLock lock = new ReentrantLock();

    private final File file;

    private long position;

    SmbFileChannel(File file, long position) {
        this.file = file;
        this.position = position;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        lock.lock();
        try {
            long read = file.read(dst, position);

            if (read >= 0) {
                position += read;
            }

            return (int) read;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        lock.lock();
        try {
            long written = file.write(src, position);
            if (written >= 0) {
                position += written;
            }

            return (int) written;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
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
    public FileChannel position(long newPosition) throws IOException {
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
    public FileChannel truncate(long size) {
        file.setLength(size);
        return this;
    }

    @Override
    public void force(boolean metaData) throws IOException {
        // there is no local buffering to flush - every read/write goes straight to the SMB server
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        throw toBeImplemented();
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        throw toBeImplemented();
    }

    @Override
    protected void implCloseChannel() throws IOException {
        // the underlying share/session is owned (and reused) by the ShareSource,
        // only the file handle belongs to this channel.
        file.close();
    }
}
