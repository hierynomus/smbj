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
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * [MS-DTYP].pdf 2.4.2 SecurityIdentifier SID
 */
public class SID {

    public enum SidType implements EnumWithValue<SidType> {
        SID_TYPE_NONE(0, "0"),
        SID_TYPE_USER(1, "User"),
        SID_TYPE_DOM_GRP(2, "Domain group"),
        SID_TYPE_DOMAIN(3, "Domain"),
        SID_TYPE_ALIAS(4, "Local group"),
        SID_TYPE_WKN_GRP(5, "Builtin group"),
        SID_TYPE_DELETED(6, "Deleted"),
        SID_TYPE_INVALID(7, "Invalid"),
        SID_TYPE_UNKNOWN(8, "Unknown"),
        SID_TYPE_COMPUTER(9, "Computer"),
        SID_TYPE_LABEL(10, "Label");

        private long value;
        private String name;

        SidType(long value, String name) {
            this.value = value;
            this.name = name;
        }

        public long getValue() {
            return value;
        }

        public String getName() {
            return name;
        }
    }

    public static final SID EVERYONE = new SID((byte) 1, new byte[]{0, 0, 0, 0, 0, 1}, new long[]{0});

    private byte revision;
    private byte[] sidIdentifierAuthority;
    private long[] subAuthorities;

    public SID() {
    }

    public SID(byte revision, byte[] sidIdentifierAuthority, long[] subAuthorities) {
        this.revision = revision;
        this.sidIdentifierAuthority = sidIdentifierAuthority;
        this.subAuthorities = subAuthorities;
    }

    private static final Pattern SID_REGEX = Pattern.compile("S-([0-9]+)-((?:0x[0-9a-fA-F]+)|(?:[0-9]+))(-[0-9]+)+");

    public static SID fromString(String sidString) {
        Matcher matcher = SID_REGEX.matcher(sidString);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid SID literal: " + sidString);
        }

        int revision = Integer.parseInt(matcher.group(1));

        String identifierAuthorityString = matcher.group(2);
        long identifierAuthorityValue;
        if (identifierAuthorityString.startsWith("0x")) {
            identifierAuthorityValue = Long.parseLong(identifierAuthorityString.substring(2), 16);
        } else {
            identifierAuthorityValue = Long.parseLong(identifierAuthorityString);
        }

        byte[] identifierAuthority = new byte[6];
        identifierAuthority[0] = (byte)((identifierAuthorityValue >> 40) & 0xFF);
        identifierAuthority[1] = (byte)((identifierAuthorityValue >> 32) & 0xFF);
        identifierAuthority[2] = (byte)((identifierAuthorityValue >> 24) & 0xFF);
        identifierAuthority[3] = (byte)((identifierAuthorityValue >> 16) & 0xFF);
        identifierAuthority[4] = (byte)((identifierAuthorityValue >> 8) & 0xFF);
        identifierAuthority[5] = (byte)(identifierAuthorityValue & 0xFF);

        String[] subAuthorityStrings = sidString.substring(matcher.end(2)).split("-");
        long[] subAuthorities = new long[subAuthorityStrings.length - 1];
        for (int i = 0; i < subAuthorities.length; i++) {
            subAuthorities[i] = Long.parseLong(subAuthorityStrings[i + 1]);
        }

        return new SID((byte)revision, identifierAuthority, subAuthorities);
    }

    public void write(SMBBuffer buffer) {
        buffer.putByte(revision); // Revision (1 byte)
        buffer.putByte((byte) subAuthorities.length); // SubAuthorityCount (1 byte)
        if (sidIdentifierAuthority.length > 6) {
            throw new IllegalArgumentException("The IdentifierAuthority can not be larger than 6 bytes");
        }
        buffer.putRawBytes(sidIdentifierAuthority); // IdentifierAuthority (6 bytes)
        for (int i = 0; i < subAuthorities.length; i++) {
            buffer.putUInt32(subAuthorities[i]); // SubAuthority (variable * 4 bytes)
        }
    }

    public static SID read(SMBBuffer buffer) throws Buffer.BufferException {
        byte revision = buffer.readByte(); // Revision (1 byte)
        int subAuthorityCount = buffer.readByte(); // SubAuthorityCount (1 byte)
        byte[] sidIdentifierAuthority = buffer.readRawBytes(6); // IdentifierAuthority (6 bytes)
        long[] subAuthorities = new long[subAuthorityCount];
        for (int i = 0; i < subAuthorityCount; i++) {
            subAuthorities[i] = buffer.readUInt32(); // SubAuthority (variable * 4 bytes)
        }
        return new SID(revision, sidIdentifierAuthority, subAuthorities);
    }

    public int byteCount() {
        return 1 + 1 + 6 + subAuthorities.length * 4;
    }

    /**
     * Return the numeric representation of this sid such as
     * <tt>S-1-5-21-1496946806-2192648263-3843101252-1029</tt>.
     */
    public String toString() {
        StringBuilder b = new StringBuilder("S-");
        b.append(revision & 0xFF).append("-");

        if (sidIdentifierAuthority[0] != (byte) 0 || sidIdentifierAuthority[1] != (byte) 0) {
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

        for (int i = 0; i < subAuthorities.length; i++)
            b.append("-").append(subAuthorities[i] & 0xFFFFFFFFL);

        return b.toString();
    }

    public byte getRevision() {
        return revision;
    }

    public byte[] getSidIdentifierAuthority() {
        return sidIdentifierAuthority;
    }

    public long[] getSubAuthorities() {
        return subAuthorities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;

        SID sid = (SID) o;

        if (revision != sid.revision)
            return false;
        if (!Arrays.equals(sidIdentifierAuthority, sid.sidIdentifierAuthority))
            return false;
        return Arrays.equals(subAuthorities, sid.subAuthorities);

    }

    @Override
    public int hashCode() {
        int result = (int) revision;
        result = 31 * result + Arrays.hashCode(sidIdentifierAuthority);
        result = 31 * result + Arrays.hashCode(subAuthorities);
        return result;
    }
}
