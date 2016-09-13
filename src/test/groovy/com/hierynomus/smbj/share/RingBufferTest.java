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
    public void shouldBeAbleToAppendAllBytesToBuffer() {
        byte[] actual = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(actual, 0, 5);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        byte[] byteArray = new byte[5];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", actual, byteArray);
    }

    @Test
    public void shouldBeAbleToAppendOnlySelectedBytesToBuffer() {
        byte[] actual = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(actual, 2, 3);
        assertEquals("Incorrect Size", 3, cBuf.getUsedSize());
        byte[] byteArray = new byte[3];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{6, 7, 1}, byteArray);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionIfBytesToWriteDoNotExist() {
        byte[] actual = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(actual, 2, 4);
    }

    @Test
    public void shouldBeAbleToAppendSingleByteToBuffer() {
        byte[] actual = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(actual, 2, 3);
        cBuf.write(2);
        assertEquals("Incorrect Size", 4, cBuf.getUsedSize());
        byte[] byteArray = new byte[4];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{6, 7, 1, 2}, byteArray);
    }

    @Test
    public void shouldBeAbleToAppendMoreBytesToExistingToBuffer() {
        byte[] b1 = new byte[]{4, 5, 6};
        cBuf.write(b1, 0, 3);
        byte[] b2 = new byte[]{12, 13};
        cBuf.write(b2, 0, 2);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        byte[] byteArray = new byte[5];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{4, 5, 6, 12, 13}, byteArray);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfBufferIsFull() {
        byte[] b = {4, 5, 6, 1, 2, 3, 4};
        cBuf.write(b, 0, 6);
        cBuf.write(b, 0, 6);
    }

    @Test
    public void shouldReadAllAvailableBytesFromBuffer() {
        byte[] b = new byte[]{4, 5, 6, 7, 1};
        cBuf.write(b, 0, 5);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        byte[] byteArray = new byte[5];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", b, byteArray);
    }

    @Test
    public void shouldReadSpecifiedNumberOfBytesFromBuffer() {
        byte[] b = new byte[]{4, 5, 6, 7, 1, 20};
        cBuf.write(b, 0, 6);
        assertEquals("Incorrect Size", 6, cBuf.getUsedSize());
        byte[] byteArray = new byte[2];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{4, 5}, byteArray);
        byteArray = new byte[3];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{6, 7, 1}, byteArray);
        byteArray = new byte[1];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{20}, byteArray);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionIfZeroBytesAreRead() {
        byte[] b = {4, 5, 6};
        cBuf.write(b, 0, 3);
        byte[] byteArray = new byte[0];
        cBuf.read(byteArray);
    }

    @Test
    public void shouldIndicateAvailableBytesCorrectly() {
        byte[] b1 = new byte[]{4, 5, 6, 10, 12};
        cBuf.write(b1, 0, 5);
        assertEquals("Incorrect Size", 5, cBuf.getUsedSize());
        cBuf.read(new byte[1]);
        assertEquals("Incorrect Size", 4, cBuf.getUsedSize());
        cBuf.read(new byte[2]);
        assertEquals("Incorrect Size", 2, cBuf.getUsedSize());
        cBuf.read(new byte[2]);
        assertEquals("Incorrect Size", 0, cBuf.getUsedSize());
    }


    @Test
    public void shouldBeAbleToAppendMoreBytesIfBytesAreRead() {
        cBuf = new RingBuffer(3);
        byte[] b1 = new byte[]{4, 5, 6};
        cBuf.write(b1, 0, 3);
        cBuf.read(new byte[1]);
        cBuf.write(new byte[]{30}, 0, 1);
        assertEquals("Incorrect Size", 3, cBuf.getUsedSize());
        byte[] byteArray = new byte[3];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{5, 6, 30}, byteArray);
    }

    @Test
    public void shouldBeAbleToAppendMoreBytesIfWritePositionHasWrappedAround() {
        cBuf = new RingBuffer(6);
        byte[] b1 = new byte[]{1, 2, 3, 4, 5, 6};
        cBuf.write(b1, 0, 6);
        cBuf.read(new byte[4]);
        cBuf.write(new byte[]{7, 8}, 0, 2);
        cBuf.write(new byte[]{9, 10}, 0, 2);
        assertEquals("Incorrect Size", 6, cBuf.getUsedSize());
        byte[] byteArray = new byte[6];
        cBuf.read(byteArray);
        assertArrayEquals("Bytes to not match", new byte[]{5, 6, 7, 8, 9, 10}, byteArray);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void shouldThrowExceptionIfFullWhenWritePositionHasWrappedAround() {
        cBuf = new RingBuffer(6);
        byte[] b1 = new byte[]{1, 2, 3, 4, 5, 6};
        cBuf.write(b1, 0, 6);
        cBuf.read(new byte[4]);
        cBuf.write(new byte[]{7, 8}, 0, 2);
        cBuf.write(new byte[]{9, 10, 11}, 0, 3);
    }

}
