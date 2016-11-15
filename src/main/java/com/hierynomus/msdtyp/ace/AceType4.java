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

import java.util.Arrays;
import java.util.EnumSet;
import java.util.UUID;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

// Type 4 - Header/Mask/Flags/ObjectType/InheritedObjectType/Sid/ApplicationData
// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE,
// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
class AceType4 extends AceType2 {

    private byte[] applicationData;

    AceType4() {
    }

    AceType4(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
             EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType, SID sid, byte[]
                 applicationData) {
        super(aceType, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid);
        aceHeader.setAceSize(aceHeader.getAceSize() + applicationData.length);
        this.applicationData = applicationData;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        super.writeTo(buffer);
        buffer.putRawBytes(applicationData);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws BufferException {
        super.readMessage(buffer);
        // application data length is derived from aceHeader.size
        applicationData = buffer.readRawBytes(aceHeader.getAceSize() - 4 + 4 + 4 + 16 + 16 + getSid().byteCount());
    }

    @Override
    public String toString() {
        return "AceType4{" +
            "applicationData=" + Arrays.toString(applicationData) +
            "} " + super.toString();
    }
}
