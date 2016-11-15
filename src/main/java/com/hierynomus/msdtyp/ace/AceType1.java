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

import java.util.EnumSet;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.BufferException;
import com.hierynomus.smbj.common.SMBBuffer;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

// Type 1 - Header/Mask/SID (ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, SYSTEM_AUDIT_ACE, SYSTEM_MANDATORY_LABEL_ACE,
// SYSTEM_SCOPED_POLICY_ID_ACE
class AceType1 extends ACE {

    AceType1() {
    }

    AceType1(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + sid.byteCount()),
            toLong(accessMask), sid);
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        getSid().write(buffer);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws BufferException {
        accessMask = buffer.readUInt32();
        getSid().read(buffer);
    }


}
