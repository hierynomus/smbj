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
import com.hierynomus.smb.SMBBuffer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * [MS-DTYP].pdf 2.4.5 ACL
 */
public class ACL {

    public static final byte ACL_REVISION = 0x02;
    public static final byte ACL_REVISION_DS = 0x04;

    private byte revision;
    private List<ACE> aces;

    public ACL(byte revision, List<ACE> aces) {
        this.revision = revision;
        this.aces = aces;
    }

    public void write(SMBBuffer buffer) {
        List<ACE> aces = this.aces == null ? Collections.<ACE>emptyList() : this.aces;
        int startPos = buffer.wpos();
        buffer.putByte(revision); // AclRevision (1 byte)
        buffer.putReserved1(); // Sbz1 (1 byte)

        int sizePos = buffer.wpos();
        buffer.wpos(sizePos + 2);
        buffer.putUInt16(aces.size()); // AceCount (2 bytes)
        buffer.putReserved2(); // Sbz2 (2 bytes)
        for (ACE ace : aces) {
            ace.write(buffer);
        }
        int endPos = buffer.wpos();
        buffer.wpos(sizePos);
        buffer.putUInt16(endPos - startPos);
        buffer.wpos(endPos);
    }

    public static ACL read(SMBBuffer buffer) throws Buffer.BufferException {
        byte revision = buffer.readByte(); // AclRevision (1 byte)
        buffer.skip(1); // Sbz1 (1 byte)
        buffer.readUInt16(); // AclSize (2 bytes)
        int aceCount = buffer.readUInt16(); // AceCount (2 bytes)
        buffer.skip(2); // Sbz2 (2 bytes)
        List<ACE> aces = new ArrayList<>(aceCount);
        for (int i = 0; i < aceCount; i++) {
            aces.add(ACE.read(buffer));
        }
        return new ACL(revision, aces);
    }

    public byte getRevision() {
        return revision;
    }

    public void setRevision(byte revision) {
        this.revision = revision;
    }

    public List<ACE> getAces() {
        return aces;
    }

    @Override
    public String toString() {
        return "ACL{" +
            "revision=" + revision +
            ", aceCount=" + aces.size() +
            ", aces=" + aces +
            '}';
    }
}
