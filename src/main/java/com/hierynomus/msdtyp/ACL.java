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

import com.hierynomus.msdtyp.ace.ACE;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.Arrays;

/**
 * [MS-DTYP].pdf 2.4.5 ACL
 */
public class ACL {

    private byte revision;
    private int aceCount;
    private byte[] sidIdentifierAuthority;
    private long[] subAuthorities;
    private ACE[] aces;
    private int aclSize;

    public void write(SMBBuffer buffer) {
        aces = aces == null ? new ACE[0] : aces;
        buffer.putByte(revision); // AclRevision (1 byte)
        buffer.putReserved1(); // Sbz1 (1 byte)
        aclSize = 8;
        for (ACE ace : aces) {
            aclSize += ace.getAceHeader().getAceSize();
        }
        buffer.putUInt16(aclSize); // AclSize (2 bytes)
        buffer.putUInt16(aces.length); // AceCount (2 bytes)
        buffer.putReserved2(); // Sbz2 (2 bytes)
        for (ACE ace : aces) {
            ace.write(buffer);
        }
    }

    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        revision = buffer.readByte(); // AclRevision (1 byte)
        buffer.skip(1); // Sbz1 (1 byte)
        aclSize = buffer.readUInt16(); // AclSize (2 bytes)
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
        return Arrays.copyOf(aces, aces.length);
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
