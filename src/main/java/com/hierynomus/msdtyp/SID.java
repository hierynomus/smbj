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
import com.hierynomus.smbj.common.Check;
import com.hierynomus.smbj.common.SMBBuffer;

/**
 * [MS-DTYP].pdf 2.4.2 SecurityIdentifier SID
 */
public class SID {

    private byte revision;
    private int subAuthorityCount;
    private byte[] sidIdentifierAuthority;
    private long[] subAuthorities;

    public void write(SMBBuffer buffer) {
        buffer.putByte(revision); // Revision (1 byte)
        buffer.putByte((byte) subAuthorityCount); // SubAuthorityCount (1 byte)
        if (sidIdentifierAuthority.length > 6) {
            throw new IllegalArgumentException("The IdentifierAuthority can not be larger than 6 bytes");
        }
        buffer.putRawBytes(sidIdentifierAuthority); // IdentifierAuthority (6 bytes)
        for (int i = 0; i < subAuthorityCount; i++) {
            buffer.putUInt32(subAuthorities[i]); // SubAuthority (variable * 4 bytes)
        }
    }

    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        revision = buffer.readByte(); // Revision (1 byte)
        subAuthorityCount = buffer.readByte(); // SubAuthorityCount (1 byte)
        sidIdentifierAuthority = buffer.readRawBytes(6); // IdentifierAuthority (6 bytes)
        subAuthorities = new long[subAuthorityCount];
        for (int i = 0; i < subAuthorityCount; i++) {
            subAuthorities[i] = buffer.readUInt32(); // SubAuthority (variable * 4 bytes)
        }
    }

    public int byteCount() {
        return 1 + 1 + 6 + subAuthorityCount * 4;
    }

    /**
     * Return the numeric representation of this sid such as
     * <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt>.
     */
    public String toString() {
        StringBuilder b = new StringBuilder("S-");
        b.append(revision & 0xFF).append("-");

        if (sidIdentifierAuthority[0] != (byte)0 || sidIdentifierAuthority[1] != (byte)0) {
            b.append("0x");
            b.append(ByteArrayUtils.printHex(sidIdentifierAuthority, 0, 6));
        } else {
            long shift = 0;
            long id = 0;
            for (int i = 5; i > 1; i--) {
                id += (sidIdentifierAuthority[i] & 0xFFL) << shift;
                shift += 8;
            }
            b.append(id);
        }

        for (int i = 0; i < subAuthorityCount ; i++)
            b.append("-").append(subAuthorities[i] & 0xFFFFFFFFL);

        return b.toString();
    }
}
