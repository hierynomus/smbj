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

import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-DTYP].pdf 2.4.4 ACE
 */
public abstract class ACE {
    private static int HEADER_STRUCTURE_SIZE = 4;

    AceHeader aceHeader = new AceHeader();

    ACE(AceHeader header) {
        this.aceHeader = header;
    }

    protected ACE() {
    }

    public final void write(SMBBuffer buffer) {
        int startPos = buffer.wpos();

        buffer.wpos(startPos + HEADER_STRUCTURE_SIZE);
        writeBody(buffer);

        int endPos = buffer.wpos();

        buffer.wpos(startPos);
        aceHeader.writeTo(buffer, endPos - startPos);
        buffer.wpos(endPos);
    }

    abstract void writeBody(SMBBuffer buffer);

    public static ACE read(SMBBuffer buffer) throws Buffer.BufferException {
        int startPos = buffer.rpos();
        AceHeader header = AceHeader.readFrom(buffer);
        ACE ace;
        switch (header.getAceType()) {
            case ACCESS_ALLOWED_ACE_TYPE:
                ace = AceType1.read(header, buffer);
                break;
            case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                ace = AceType3.read(header, buffer, startPos);
                break;
            case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                ace = AceType4.read(header, buffer, startPos);
                break;
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                ace = AceType2.read(header, buffer, startPos);
                break;
            case ACCESS_DENIED_ACE_TYPE:
                ace = AceType1.read(header, buffer);
                break;
            case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                ace = AceType3.read(header, buffer, startPos);
                break;
            case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                ace = AceType4.read(header, buffer, startPos);
                break;
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                ace = AceType2.read(header, buffer, startPos);
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                ace = AceType1.read(header, buffer);
                break;
            case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                ace = AceType3.read(header, buffer, startPos);
                break;
            case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                ace = AceType4.read(header, buffer, startPos);
                break;
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                ace = AceType4.read(header, buffer, startPos);
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                ace = AceType1.read(header, buffer);
                break;
            case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                ace = AceType3.read(header, buffer, startPos);
                break;
            case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                ace = AceType1.read(header, buffer);
                break;
            default:
                throw new IllegalStateException("Unknown ACE type: " + header.getAceType());
        }

        return ace;
    }

    public AceHeader getAceHeader() {
        return aceHeader;
    }

    public abstract SID getSid();

    public abstract long getAccessMask();
}


