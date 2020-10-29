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
package com.hierynomus.mssmb2.messages.submodule;

import com.hierynomus.mssmb2.SMB2LockFlag;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public class SMB2LockElement {
    private static final List<EnumSet<SMB2LockFlag>> VALID_FLAG_COMBINATIONS = Arrays.asList(
        EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_SHARED_LOCK),
        EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_EXCLUSIVE_LOCK),
        EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_SHARED_LOCK, SMB2LockFlag.SMB2_LOCKFLAG_FAIL_IMMEDIATELY),
        EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_EXCLUSIVE_LOCK, SMB2LockFlag.SMB2_LOCKFLAG_FAIL_IMMEDIATELY),
        EnumSet.of(SMB2LockFlag.SMB2_LOCKFLAG_UNLOCK)
    );


    private final long offset;
    private final long length;
    private final Set<SMB2LockFlag> lockFlags;

    public SMB2LockElement(long offset, long length, Set<SMB2LockFlag> lockFlags) {
        this.offset = offset;
        this.length = length;
        EnumSet<SMB2LockFlag> enumLockFlags = lockFlags != null ? EnumSet.copyOf(lockFlags) : EnumSet.noneOf(SMB2LockFlag.class);
        if(!VALID_FLAG_COMBINATIONS.contains(enumLockFlags)) {
            throw new IllegalArgumentException("Invalid lock flags combination. Check SMB2 document 2.2.26.1 SMB2_LOCK_ELEMENT Structure.");
        }
        this.lockFlags = lockFlags;
    }

    public long getOffset() {
        return offset;
    }

    public long getLength() {
        return length;
    }

    public Set<SMB2LockFlag> getLockFlags() {
        return lockFlags;
    }

    @Override
    public String toString() {
        return "SMB2LockElement{" + "offset=" + offset + ", length=" + length + ", lockFlags="
               + lockFlags + '}';
    }
}
