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

// Type 3 - Header/Mask/SID/ApplicationData
// (ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_ACE)
class AceType3 extends ACE {

    private long accessMask;
    private SID sid;
    private byte[] applicationData;

    AceType3(AceHeader header, long accessMask, SID sid, byte[] applicationData) {
        super(header);
        this.accessMask = accessMask;
        this.sid = sid;
        this.applicationData = applicationData;
    }

    @Override
    protected void writeBody(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        sid.write(buffer);
        buffer.putRawBytes(applicationData);
    }

    static AceType3 read(AceHeader header, SMBBuffer buffer, int aceStartPos) throws Buffer.BufferException {
        long accessMask = buffer.readUInt32();
        SID sid = SID.read(buffer);
        int applicationDataSize = header.getAceSize() - (buffer.rpos() - aceStartPos);
        byte[] applicationData = buffer.readRawBytes(applicationDataSize);
        return new AceType3(header, accessMask, sid, applicationData);
    }

    @Override
    public String toString() {
        return String.format(
            "AceType3{type=%s, flags=%s, access=0x%x, sid=%s, data=%s}",
            aceHeader.getAceType(),
            aceHeader.getAceFlags(),
            accessMask,
            sid,
            Arrays.toString(applicationData)
        );
    }

    @Override
    public SID getSid() {
        return sid;
    }

    @Override
    public long getAccessMask() {
        return accessMask;
    }

    public byte[] getApplicationData() {
        return applicationData;
    }
}
