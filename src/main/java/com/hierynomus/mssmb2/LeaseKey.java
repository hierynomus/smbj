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
package com.hierynomus.mssmb2;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

import com.hierynomus.protocol.commons.ByteArrayUtils;

/**
 * A 16-byte SMB2 lease key ([MS-SMB2] 2.2.13.2.8). Value object so it can key a
 * {@code Map<LeaseKey, ...>} lease table and match an inbound lease-break's LeaseKey.
 * Per Apple's reference client, a lease key is minted per-node (per file/directory)
 * and reused for that node's lifetime.
 */
public final class LeaseKey {
    public static final int SIZE = 16;

    private final byte[] key;

    public LeaseKey(byte[] key) {
        if (key == null || key.length != SIZE) {
            throw new IllegalArgumentException("A lease key must be exactly " + SIZE + " bytes");
        }
        this.key = key.clone();
    }

    /** Mint a fresh random per-node lease key. */
    public static LeaseKey random() {
        return fromUuid(UUID.randomUUID());
    }

    public static LeaseKey fromUuid(UUID uuid) {
        ByteBuffer bb = ByteBuffer.allocate(SIZE); // big-endian
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return new LeaseKey(bb.array());
    }

    /** The canonical all-zero key, meaning "no (parent) lease key". */
    public static LeaseKey zero() {
        return new LeaseKey(new byte[SIZE]);
    }

    public byte[] getBytes() {
        return key.clone();
    }

    public boolean isAllZero() {
        for (byte b : key) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof LeaseKey)) {
            return false;
        }
        return Arrays.equals(key, ((LeaseKey) o).key);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }

    @Override
    public String toString() {
        return "LeaseKey{" + ByteArrayUtils.toHex(key) + "}";
    }
}
