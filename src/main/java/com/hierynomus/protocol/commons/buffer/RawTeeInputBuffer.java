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
package com.hierynomus.protocol.commons.buffer;

public class RawTeeInputBuffer implements RawInputBuffer {
    private final RawInputBuffer source;
    private final RawOutputBuffer sink;

    public RawTeeInputBuffer(RawInputBuffer source, RawOutputBuffer sink) {
        this.source = source;
        this.sink = sink;
    }

    @Override
    public int available() {
        return source.available();
    }

    @Override
    public int rpos() {
        return source.rpos();
    }

    @Override
    public void rpos(final int rpos) {
        source.rpos(rpos);
    }

    @Override
    public byte readByte() throws BufferException {
        byte b = source.readByte();
        sink.putByte(b);
        return b;
    }

    @Override
    public byte[] readRawBytes(final int length) throws BufferException {
        byte[] bytes = source.readRawBytes(length);
        sink.putRawBytes(bytes);
        return bytes;
    }

    @Override
    public void readRawBytes(final byte[] buf) throws BufferException {
        source.readRawBytes(buf);
        sink.putRawBytes(buf);
    }

    @Override
    public void readRawBytes(final byte[] buf, final int offset, final int length) throws BufferException {
        source.readRawBytes(buf, offset, length);
        sink.putRawBytes(buf, offset, length);
    }

    @Override
    public void skip(final int length) throws BufferException {
        source.skip(length);
    }
}
