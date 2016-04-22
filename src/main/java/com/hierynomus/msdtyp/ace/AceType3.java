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
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.Arrays;
import java.util.EnumSet;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

// Type 3 - Header/Mask/SID/ApplicationData
// (ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_ACE)
class AceType3 extends ACE {

    private byte[] applicationData;

    AceType3() {
    }

    AceType3(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid, byte[]
            applicationData) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + 4 + sid.byteCount() +
                        applicationData.length),
                toLong(accessMask), sid);
        this.applicationData = applicationData;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        getSid().write(buffer);
        buffer.putRawBytes(applicationData);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();
        getSid().read(buffer);
        applicationData = buffer.readRawBytes(aceHeader.getAceSize() - 4 + 4 + getSid().byteCount());
    }

    @Override
    public String toString() {
        return "AceType3{" +
                "applicationData=" + Arrays.toString(applicationData) +
                "} " + super.toString();
    }
}
