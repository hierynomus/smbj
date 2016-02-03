/*
 * Copyright (C)2016 - Jeroen van Erp <jeroen@hierynomus.com>
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

import java.nio.charset.Charset;

/**
 * Buffer helper class to read/write bytes in correct endian order.
 */
public abstract class Endian {

    public static final Endian LE = new Little();
    public static final Endian BE = new Big();

    public static class Big extends Endian {

        @Override
        public <T extends Buffer<T>> void writeUInt16(Buffer<T> buffer, int uint16) {
            buffer.ensureCapacity(2);
            if (uint16 < 0 || uint16 > 0xFFFF) {
                throw new RuntimeException("Invalid uint16 value: " + uint16);
            }
            buffer.data[buffer.wpos++] = (byte) (uint16 >> 8);
            buffer.data[buffer.wpos++] = (byte) uint16;
        }

        @Override
        public <T extends Buffer<T>> int readUInt16(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(2);
            return buffer.data[buffer.rpos++] << 8 & 0xFF00 |
                    buffer.data[buffer.rpos++] & 0x00FF;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt24(Buffer<T> buffer, int uint24) {
            buffer.ensureCapacity(3);
            if (uint24 < 0 || uint24 > 0xFFFFFF)
                throw new RuntimeException("Invalid uint24 value: " + uint24);
            buffer.data[buffer.wpos++] = (byte) (uint24 >> 16);
            buffer.data[buffer.wpos++] = (byte) (uint24 >> 8);
            buffer.data[buffer.wpos++] = (byte) uint24;
        }

        @Override
        public <T extends Buffer<T>> int readUInt24(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(3);
            return buffer.data[buffer.rpos++] << 16 & 0xFF0000 |
                    buffer.data[buffer.rpos++] << 8 & 0x00FF00 |
                    buffer.data[buffer.rpos++] & 0x0000FF;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt32(Buffer<T> buffer, long uint32) {
            buffer.ensureCapacity(4);
            if (uint32 < 0 || uint32 > 0xFFFFFFFFL)
                throw new RuntimeException("Invalid uint32 value: " + uint32);
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 24);
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 16);
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 8);
            buffer.data[buffer.wpos++] = (byte) uint32;
        }

        @Override
        public <T extends Buffer<T>> long readUInt32(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(4);
            return buffer.data[buffer.rpos++] << 24 & 0xFF000000L |
                    buffer.data[buffer.rpos++] << 16 & 0x00FF0000L |
                    buffer.data[buffer.rpos++] << 8 & 0x0000FF00L |
                    buffer.data[buffer.rpos++] & 0x000000FFL;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt64(Buffer<T> buffer, long uint64) {
            if (uint64 < 0)
                throw new RuntimeException("Invalid uint64 value: " + uint64);
            writeLong(buffer, uint64);
        }

        @Override
        public <T extends Buffer<T>> long readUInt64(Buffer<T> buffer) throws Buffer.BufferException {
            long uint64 = (readUInt32(buffer) << 32) + (readUInt32(buffer) & 0xFFFFFFFFL);
            if (uint64 < 0)
                throw new Buffer.BufferException("Cannot handle values > " + Long.MAX_VALUE);
            return uint64;
        }

        @Override
        public <T extends Buffer<T>> void writeLong(Buffer<T> buffer, long longVal) {
            buffer.ensureCapacity(8);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 56);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 48);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 40);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 32);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 24);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 16);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 8);
            buffer.data[buffer.wpos++] = (byte) longVal;
        }

        @Override
        public <T extends Buffer<T>> long readLong(Buffer<T> buffer) throws Buffer.BufferException {
            long result = 0;
            for (int i = 0; i < 8; i++) {
                result <<= 8;
                result |= (buffer.data[buffer.rpos++] & 0xFF);
            }
            return result;
        }

        @Override
        public <T extends Buffer<T>> String readUtf16String(Buffer<T> buffer, int length) throws Buffer.BufferException {
            byte[] stringBytes = new byte[length * 2];
            buffer.readRawBytes(stringBytes);
            return new String(stringBytes, Charset.forName("UTF-16BE"));
        }

        @Override
        public <T extends Buffer<T>> void writeUtf16String(Buffer<T> buffer, String string) {
            byte[] bytes = string.getBytes(Charset.forName("UTF-16BE"));
            buffer.putRawBytes(bytes);
        }

        @Override
        public String toString() {
            return "big endian";
        }
    }

    public static class Little extends Endian {

        @Override
        public <T extends Buffer<T>> void writeUInt16(Buffer<T> buffer, int uint16) {
            buffer.ensureCapacity(2);
            if (uint16 < 0 || uint16 > 0xFFFF) {
                throw new RuntimeException("Invalid uint16 value: " + uint16);
            }
            buffer.data[buffer.wpos++] = (byte) uint16;
            buffer.data[buffer.wpos++] = (byte) (uint16 >> 8);
        }

        @Override
        public <T extends Buffer<T>> int readUInt16(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(2);
            return buffer.data[buffer.rpos++] & 0x00FF |
                    buffer.data[buffer.rpos++] << 8 & 0xFF00;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt24(Buffer<T> buffer, int uint24) {
            buffer.ensureCapacity(3);
            if (uint24 < 0 || uint24 > 0xFFFFFF)
                throw new RuntimeException("Invalid uint24 value: " + uint24);
            buffer.data[buffer.wpos++] = (byte) uint24;
            buffer.data[buffer.wpos++] = (byte) (uint24 >> 8);
            buffer.data[buffer.wpos++] = (byte) (uint24 >> 16);

        }

        @Override
        public <T extends Buffer<T>> int readUInt24(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(3);
            return buffer.data[buffer.rpos++] & 0x0000FF |
                    buffer.data[buffer.rpos++] << 8 & 0x00FF00 |
                    buffer.data[buffer.rpos++] << 16 & 0xFF0000;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt32(Buffer<T> buffer, long uint32) {
            buffer.ensureCapacity(4);
            if (uint32 < 0 || uint32 > 0xFFFFFFFFL)
                throw new RuntimeException("Invalid uint32 value: " + uint32);
            buffer.data[buffer.wpos++] = (byte) uint32;
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 8);
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 16);
            buffer.data[buffer.wpos++] = (byte) (uint32 >> 24);

        }

        @Override
        public <T extends Buffer<T>> long readUInt32(Buffer<T> buffer) throws Buffer.BufferException {
            buffer.ensureAvailable(4);
            return buffer.data[buffer.rpos++] & 0x000000FFL |
                    buffer.data[buffer.rpos++] << 8 & 0x0000FF00L |
                    buffer.data[buffer.rpos++] << 16 & 0x00FF0000L |
                    buffer.data[buffer.rpos++] << 24 & 0xFF000000L;
        }

        @Override
        public <T extends Buffer<T>> void writeUInt64(Buffer<T> buffer, long uint64) {
            if (uint64 < 0)
                throw new RuntimeException("Invalid uint64 value: " + uint64);
            writeLong(buffer, uint64);
        }

        @Override
        public <T extends Buffer<T>> long readUInt64(Buffer<T> buffer) throws Buffer.BufferException {
            long uint64 = (readUInt32(buffer) & 0xFFFFFFFFL) + (readUInt32(buffer) << 32);
            if (uint64 < 0)
                throw new Buffer.BufferException("Cannot handle values > " + Long.MAX_VALUE);
            return uint64;
        }

        @Override
        public <T extends Buffer<T>> void writeLong(Buffer<T> buffer, long longVal) {
            buffer.ensureCapacity(8);
            buffer.data[buffer.wpos++] = (byte) longVal;
            buffer.data[buffer.wpos++] = (byte) (longVal >> 8);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 16);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 24);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 32);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 40);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 48);
            buffer.data[buffer.wpos++] = (byte) (longVal >> 56);

        }

        @Override
        public <T extends Buffer<T>> long readLong(Buffer<T> buffer) throws Buffer.BufferException {
            long result = 0;
            byte[] bytes = buffer.readRawBytes(8);
            for (int i = 7; i >= 0; i++) {
                result <<= 8;
                result |= (bytes[i] & 0xFF);
            }
            return result;

        }

        @Override
        public <T extends Buffer<T>> String readUtf16String(Buffer<T> buffer, int length) throws Buffer.BufferException {
            byte[] stringBytes = new byte[length * 2];
            buffer.readRawBytes(stringBytes);
            return new String(stringBytes, Charset.forName("UTF-16LE"));
        }

        @Override
        public <T extends Buffer<T>> void writeUtf16String(Buffer<T> buffer, String string) {
            byte[] bytes = string.getBytes(Charset.forName("UTF-16LE"));
            buffer.putRawBytes(bytes);
        }

        @Override
        public String toString() {
            return "little endian";
        }
    }

    public abstract <T extends Buffer<T>> void writeUInt16(Buffer<T> buffer, int uint16);

    public abstract <T extends Buffer<T>> int readUInt16(Buffer<T> buffer) throws Buffer.BufferException;

    public abstract <T extends Buffer<T>> void writeUInt24(Buffer<T> buffer, int uint24);

    public abstract <T extends Buffer<T>> int readUInt24(Buffer<T> buffer) throws Buffer.BufferException;

    public abstract <T extends Buffer<T>> void writeUInt32(Buffer<T> buffer, long uint32);

    public abstract <T extends Buffer<T>> long readUInt32(Buffer<T> buffer) throws Buffer.BufferException;

    public abstract <T extends Buffer<T>> void writeUInt64(Buffer<T> buffer, long uint64);

    public abstract <T extends Buffer<T>> long readUInt64(Buffer<T> buffer) throws Buffer.BufferException;

    public abstract <T extends Buffer<T>> void writeLong(Buffer<T> buffer, long longVal);

    public abstract <T extends Buffer<T>> long readLong(Buffer<T> buffer) throws Buffer.BufferException;

    public abstract <T extends Buffer<T>> void writeUtf16String(Buffer<T> buffer, String string);

    public abstract <T extends Buffer<T>> String readUtf16String(Buffer<T> buffer, int length) throws Buffer.BufferException;

}
