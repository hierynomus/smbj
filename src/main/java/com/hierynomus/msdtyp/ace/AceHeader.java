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
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.EnumSet;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

/**
 * [MS-DTYP].pdf 2.4.4.1 ACE_HEADER
 */
public class AceHeader {

    private AceType aceType;
    private EnumSet<AceFlags> aceFlags;
    private int aceSize;

    AceHeader() {
    }

    AceHeader(AceType aceType, EnumSet<AceFlags> aceFlags, int aceSize) {
        this.aceType = aceType;
        this.aceFlags = aceFlags;
        this.aceSize = aceSize;
    }

    public void writeTo(SMBBuffer buffer) {
        buffer.putByte((byte) aceType.getValue());
        buffer.putByte((byte) EnumWithValue.EnumUtils.toLong(aceFlags));
        buffer.putUInt16(aceSize);
    }

    public void readFrom(SMBBuffer buffer) throws Buffer.BufferException {
        this.aceType = valueOf(buffer.readByte(), AceType.class, null);
        this.aceFlags = toEnumSet(buffer.readByte(), AceFlags.class);
        this.aceSize = buffer.readUInt16();
    }

    public int getAceSize() {
        return aceSize;
    }

    void setAceSize(int aceSize) {
        this.aceSize = aceSize;
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
