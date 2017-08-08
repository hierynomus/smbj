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

// Type 1 - Header/Mask/SID (ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, SYSTEM_AUDIT_ACE, SYSTEM_MANDATORY_LABEL_ACE,
// SYSTEM_SCOPED_POLICY_ID_ACE
class AceType1 extends ACE {

    private long accessMask;
    private SID sid;

    AceType1(AceHeader header, long accessMask, SID sid) {
        super(header);
        this.accessMask = accessMask;
        this.sid = sid;
    }

    @Override
    protected void writeBody(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        sid.write(buffer);
    }

    static AceType1 read(AceHeader header, SMBBuffer buffer) throws Buffer.BufferException {
        long accessMask = buffer.readUInt32();
        SID sid = SID.read(buffer);
        return new AceType1(header, accessMask, sid);
    }

    @Override
    public SID getSid() {
        return sid;
    }

    @Override
    public long getAccessMask() {
        return accessMask;
    }

    @Override
    public String toString() {
        return String.format(
            "AceType1{type=%s, flags=%s, access=0x%x, sid=%s}",
            aceHeader.getAceType(),
            aceHeader.getAceFlags(),
            accessMask,
            sid
        );
    }
}
