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
package com.hierynomus.msdtyp;

import com.hierynomus.protocol.commons.ByteArrayUtils;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.Arrays;

/**
 * [MS-DTYP].pdf 2.4.5 ACL
 */
public class ACL {

    byte revision;
    int aceCount;
    byte[] sidIdentifierAuthority;
    long[] subAuthorities;
    ACE[] aces;
    int aclSize;

    public void write(SMBBuffer buffer) {
        buffer.putByte(revision);
        buffer.putByte((byte)0);
        aclSize = 8;
        for (int i = 0; i < aces.length; i++) {
            aclSize += aces[i].getAceHeader().getAceSize();
        }
        buffer.putUInt16(aclSize);
        buffer.putUInt16(aces.length);
        buffer.putUInt16(0);
        for (int i = 0; i < aces.length; i++) {
            aces[i].write(buffer);
        }
    }

    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        revision = buffer.readByte(); // AclRevision (1 byte)
        buffer.skip(1); // Sbz1 (1 byte)
        aclSize = buffer.readUInt16(); // AclSize (1 byte)
        int aceCount = buffer.readUInt16(); // AceCount (2 bytes)
        buffer.skip(2); // Sbz2 (2 bytes)
        aces = new ACE[aceCount];
        for (int i = 0; i < aceCount; i++) {
            aces[i] = ACE.factory(buffer);
        }
    }

    public int getAceCount() {
        return aceCount;
    }

    public byte[] getSidIdentifierAuthority() {
        return sidIdentifierAuthority;
    }

    public long[] getSubAuthorities() {
        return subAuthorities;
    }

    public ACE[] getAces() {
        return aces;
    }

    public int getAclSize() {
        return aclSize;
    }

    @Override
    public String toString() {
        return "ACL{" +
                "revision=" + revision +
                ", aceCount=" + aceCount +
                ", sidIdentifierAuthority=" + Arrays.toString(sidIdentifierAuthority) +
                ", subAuthorities=" + Arrays.toString(subAuthorities) +
                ", aces=" + Arrays.toString(aces) +
                '}';
    }
}
