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
 * {@code Files.newByteChannel(...) instanceof FileChannel}. {@link #map} and the byte-range
 * {@link #lock}/{@link #tryLock} operations have no implementation yet - the former cannot
 * be implemented outside the JDK (there is no local memory-mapped file), and the latter
 * would require exposing SMB2 byte-range locking (already implemented internally for
 * {@code com.hierynomus.smbj.share.Share}) on the public {@code File} API first - both
 * throw {@link ToBeImplementedException}.
 */
class SmbFileChannel extends FileChannel {

    /** Buffer size used to chunk {@link #transferTo}/{@link #transferFrom}. */
    private static final int TRANSFER_BUFFER_SIZE = 64 * 1024;

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
        checkIndices(dsts.length, offset, length);

        long total = 0;
        for (int i = offset; i < offset + length; i++) {
            ByteBuffer dst = dsts[i];
            while (dst.hasRemaining()) {
                int read = read(dst);
                if (read < 0) {
                    return total == 0 ? -1 : total;
                }

                total += read;
                if (read == 0) {
                    break;
                }
            }
        }

        return total;
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
        checkIndices(srcs.length, offset, length);

        long total = 0;
        for (int i = offset; i < offset + length; i++) {
            ByteBuffer src = srcs[i];
            while (src.hasRemaining()) {
                int written = write(src);
                total += written;
                if (written == 0) {
                    break;
                }
            }
        }

        return total;
    }

    private static void checkIndices(int arrayLength, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > arrayLength) {
            throw new IndexOutOfBoundsException(
                "offset=" + offset + ", length=" + length + ", arrayLength=" + arrayLength);
        }
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
        if (position < 0 || count < 0) {
            throw new IllegalArgumentException("position=" + position + ", count=" + count);
        }

        long remaining = count;
        long pos = position;
        long transferred = 0;
        ByteBuffer buffer = ByteBuffer.allocate((int) Math.min(TRANSFER_BUFFER_SIZE, Math.max(count, 1)));

        while (remaining > 0) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), remaining));

            int read = read(buffer, pos);
            if (read < 0) {
                break;
            }

            buffer.flip();
            while (buffer.hasRemaining()) {
                target.write(buffer);
            }

            pos += read;
            remaining -= read;
            transferred += read;
        }

        return transferred;
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        if (position < 0 || count < 0) {
            throw new IllegalArgumentException("position=" + position + ", count=" + count);
        }

        long remaining = count;
        long pos = position;
        long transferred = 0;
        ByteBuffer buffer = ByteBuffer.allocate((int) Math.min(TRANSFER_BUFFER_SIZE, Math.max(count, 1)));

        while (remaining > 0) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), remaining));

            int read = src.read(buffer);
            if (read < 0) {
                break;
            }

            buffer.flip();
            while (buffer.hasRemaining()) {
                int written = write(buffer, pos);
                pos += written;
                transferred += written;
            }

            remaining -= read;
        }

        return transferred;
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("position=" + position);
        }

        // positional read/write don't affect (and aren't affected by) the channel's
        // current position, so no need to hold the position lock here.
        long read = file.read(dst, position);
        return (int) read;
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("position=" + position);
        }

        long written = file.write(src, position);
        return (int) written;
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
