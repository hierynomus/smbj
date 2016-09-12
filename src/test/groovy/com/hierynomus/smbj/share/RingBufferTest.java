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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class RingBufferTest {

    private RingBuffer cBuf;

    @Before
    public void setUp() {
        cBuf = new RingBuffer(10);
    }

    @Test
    public void shouldBeAbleStartAppendingBytesToBuffer() {
        byte[] actual = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(actual);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", actual, cBuf.read(5));
    }

    @Test
    public void shouldBeAbleToAppendMoreBytesToExistingToBuffer() {
        byte[] b1 = new byte[]{4, 5, 6};
        cBuf.write(b1);
        byte[] b2 = new byte[]{12, 13};
        cBuf.write(b2);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", new byte[]{4, 5, 6, 12, 13}, cBuf.read(5));
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfBufferIsFull() {
        byte[] b = {4, 5, 6, 1, 2, 3, 4};
        cBuf.write(b);
        cBuf.write(b);
    }

    @Test
    public void shouldReadAllAvailableBytesFromBuffer() {
        byte[] b = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(b);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", b, cBuf.read(5));
    }

    @Test
    public void shouldReadSpecifiedNumberOfBytesFromBuffer() {
        byte[] b = new byte[]{4, 5, 6, 7, 1, 20};
        cBuf.write(b);
        assertEquals("Incorrect Size", 6, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", new byte[]{4, 5}, cBuf.read(2));
        assertArrayEquals("Bytes to not match", new byte[]{6, 7, 1}, cBuf.read(3));
        assertArrayEquals("Bytes to not match", new byte[]{20}, cBuf.read(1));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionIfZeroBytesAreRead() {
        byte[] b = {4, 5, 6};
        cBuf.write(b);
        cBuf.read(0);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfAllBytesAreRead() {
        byte[] b = {4, 5, 6};
        cBuf.write(b);
        assertArrayEquals("Bytes to not match", new byte[]{4, 5}, cBuf.read(2));
        cBuf.read(3);
    }

    @Test
    public void shouldIndicateAvailableBytesCorrectly() {
        byte[] b1 = new byte[]{4, 5, 6, 10, 12};
        cBuf.write(b1);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        cBuf.read(1);
        assertEquals("Incorrect Size", 4, cBuf.getUsedSize());
        cBuf.read(2);
        assertEquals("Incorrect Size", 2, cBuf.getUsedSize());
        cBuf.read(2);
        assertEquals("Incorrect Size", 0, cBuf.getUsedSize());
    }


    @Test
    public void shouldBeAbleToAppendMoreBytesIfBytesAreRead() {
        cBuf = new RingBuffer(3);
        byte[] b1 = new byte[]{4, 5, 6};
        cBuf.write(b1);
        cBuf.read(1);
        cBuf.write(new byte[]{30});
        assertEquals("Incorrect Size", 3, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", new byte[]{5, 6, 30}, cBuf.read(3));
    }

    @Test
    public void shouldBeAbleToAppendMoreBytesIfWritePositionHasWrappedAround() {
        cBuf = new RingBuffer(6);
        byte[] b1 = new byte[]{1, 2, 3, 4, 5, 6};
        cBuf.write(b1);
        cBuf.read(4);
        cBuf.write(new byte[]{7, 8});
        cBuf.write(new byte[]{9, 10});
        assertEquals("Incorrect Size", 6, cBuf.getUsedSize());
        assertArrayEquals("Bytes to not match", new byte[]{5, 6, 7, 8, 9, 10}, cBuf.read(6));
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfFullWhenWritePositionHasWrappedAround() {
        cBuf = new RingBuffer(6);
        byte[] b1 = new byte[]{1, 2, 3, 4, 5, 6};
        cBuf.write(b1);
        cBuf.read(4);
        cBuf.write(new byte[]{7, 8});
        cBuf.write(new byte[]{9, 10, 11});
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfAllBytesAreReadWhenWritePositionHasWrappedAround() {
        cBuf = new RingBuffer(6);
        byte[] b1 = new byte[]{1, 2, 3, 4, 5, 6};
        cBuf.write(b1);
        cBuf.read(4);
        cBuf.write(new byte[]{7, 8});
        cBuf.read(5);
    }
}
