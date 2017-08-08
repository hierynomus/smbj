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
package com.hierynomus.msdtyp.ace;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.Set;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

/**
 * [MS-DTYP].pdf 2.4.4.1 ACE_HEADER
 */
public class AceHeader {

    private AceType aceType;
    private Set<AceFlags> aceFlags;
    private int aceSize;

    AceHeader() {
    }

    AceHeader(AceType aceType, Set<AceFlags> aceFlags) {
        this.aceType = aceType;
        this.aceFlags = aceFlags;
    }

    public void writeTo(SMBBuffer buffer) {
        writeTo(buffer, aceSize);
    }

    void writeTo(SMBBuffer buffer, int aceSize) {
        buffer.putByte((byte) aceType.getValue());
        buffer.putByte((byte) EnumWithValue.EnumUtils.toLong(aceFlags));
        buffer.putUInt16(aceSize);
    }

    static AceHeader readFrom(SMBBuffer buffer) throws Buffer.BufferException {
        AceType aceType = valueOf(buffer.readByte(), AceType.class, null);
        Set<AceFlags> aceFlags = toEnumSet(buffer.readByte(), AceFlags.class);
        int aceSize = buffer.readUInt16();
        AceHeader header = new AceHeader(aceType, aceFlags);
        header.aceSize = aceSize;
        return header;
    }

    public int getAceSize() {
        return aceSize;
    }

    public AceType getAceType() {
        return aceType;
    }

    public Set<AceFlags> getAceFlags() {
        return aceFlags;
    }

    @Override
    public String toString() {
        return "AceHeader{" +
            "aceType=" + aceType +
            ", aceFlags=" + aceFlags +
            ", aceSize=" + aceSize +
            '}';
    }
}
