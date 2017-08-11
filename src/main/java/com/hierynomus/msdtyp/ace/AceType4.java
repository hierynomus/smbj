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

import java.util.Arrays;
import java.util.UUID;

// Type 4 - Header/Mask/Flags/ObjectType/InheritedObjectType/Sid/ApplicationData
// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE,
// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
class AceType4 extends AceType2 {

    private byte[] applicationData;

    private AceType4(AceHeader header) {
        super(header);
    }

    AceType4(AceHeader header, long accessMask, UUID objectType, UUID inheritedObjectType, SID sid, byte[] applicationData) {
        super(header, accessMask, objectType, inheritedObjectType, sid);
        this.applicationData = applicationData;
    }

    @Override
    void writeBody(SMBBuffer buffer) {
        super.writeBody(buffer);
        buffer.putRawBytes(applicationData);
    }

    @Override
    protected void readBody(SMBBuffer buffer, int aceStartPos) throws Buffer.BufferException {
        super.readBody(buffer, aceStartPos);
        int applicationDataSize = aceHeader.getAceSize() - (buffer.rpos() - aceStartPos);
        applicationData = buffer.readRawBytes(applicationDataSize);
    }

    static AceType4 read(AceHeader header, SMBBuffer buffer, int aceStartPos) throws Buffer.BufferException {
        AceType4 ace = new AceType4(header);
        ace.readBody(buffer, aceStartPos);
        return ace;
    }

    @Override
    public String toString() {
        return String.format(
            "AceType4{type=%s, flags=%s, access=0x%x, objectType=%s, inheritedObjectType=%s, sid=%s, data=%s}",
            aceHeader.getAceType(),
            aceHeader.getAceFlags(),
            accessMask,
            objectType,
            inheritedObjectType,
            sid,
            Arrays.toString(applicationData)
        );
    }

    public byte[] getApplicationData() {
        return applicationData;
    }
}
