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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

/**
 * [MS-DTYP].pdf 2.4.4 ACE
 */
public abstract class ACE {

    static int HEADER_STRUCTURE_SIZE = 4;

    AceHeader aceHeader = new AceHeader();

    long accessMask;
    private SID sid = new SID();

    ACE(AceHeader aceHeader, long accessMask, SID sid) {
        this.aceHeader = aceHeader;
        this.accessMask = accessMask;
        this.sid = sid;
    }

    protected ACE() {
    }

    public final void write(SMBBuffer buffer) {
        aceHeader.writeTo(buffer);
        writeTo(buffer);
    }

    protected abstract void writeTo(SMBBuffer buffer);

    public final ACE read(SMBBuffer buffer) throws Buffer.BufferException {
        aceHeader.readFrom(buffer);
        readMessage(buffer);
        return this;
    }

    public static ACE factory(SMBBuffer buffer) throws Buffer.BufferException {
        AceType aceType = valueOf(buffer.readByte(), AceType.class, null);
        buffer.rpos(buffer.rpos() - 1); // Go back
        ACE ace = null;
        switch (aceType) {
            case ACCESS_ALLOWED_ACE_TYPE:
                ace = new AceType1().read(buffer);
                break;
            case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                ace = new AceType3().read(buffer);
                break;
            case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                ace = new AceType4().read(buffer);
                break;
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                ace = new AceType2().read(buffer);
                break;
            case ACCESS_DENIED_ACE_TYPE:
                ace = new AceType1().read(buffer);
                break;
            case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                ace = new AceType3().read(buffer);
                break;
            case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                ace = new AceType4().read(buffer);
                break;
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                ace = new AceType2().read(buffer);
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                ace = new AceType1().read(buffer);
                break;
            case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                ace = new AceType3().read(buffer);
                break;
            case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                ace = new AceType4().read(buffer);
                break;
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                ace = new AceType4().read(buffer);
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                ace = new AceType1().read(buffer);
                break;
            case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                ace = new AceType3().read(buffer);
                break;
            case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                ace = new AceType1().read(buffer);
                break;
            default:
                throw new IllegalStateException("Unknown ACE type: " + aceType);
        }

        return ace;
    }

    @Override
    public String toString() {
        return "ACE{" +
                "aceHeader=" + aceHeader +
                ", accessMask=" + EnumWithValue.EnumUtils.toEnumSet(accessMask, AccessMask.class) +
                ", sid=" + sid +
                '}';
    }

    protected abstract void readMessage(SMBBuffer buffer) throws Buffer.BufferException;

    public AceHeader getAceHeader() {
        return aceHeader;
    }

    public SID getSid() {
        return sid;
    }

    public long getAccessMask() {
        return accessMask;
    }
}


