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
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.EnumSet;
import java.util.UUID;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

// Type 2 - Header/Mask/Flags/ObjectType/InheritedObjectType/SID
// (ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE)
class AceType2 extends ACE {
    private EnumSet<AceObjectFlags> flags;
    private UUID objectType;
    private UUID inheritedObjectType;

    AceType2(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                    EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType, SID sid) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + 4 + 16 + 16 + sid.byteCount()),
                toLong(accessMask), sid);
        this.flags = flags;
        this.objectType = objectType;
        this.inheritedObjectType = inheritedObjectType;
    }

    AceType2() {
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        buffer.putUInt32(toLong(flags));
        MsDataTypes.putGuid(objectType, buffer);
        MsDataTypes.putGuid(inheritedObjectType, buffer);
        getSid().write(buffer);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();
        flags = toEnumSet(buffer.readUInt32(), AceObjectFlags.class);
        if (flags.contains(AceObjectFlags.ACE_OBJECT_TYPE_PRESENT)) {
            objectType = MsDataTypes.readGuid(buffer);
        } else {
            buffer.skip(16);
        }
        if (flags.contains(AceObjectFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
            inheritedObjectType = MsDataTypes.readGuid(buffer);
        } else {
            buffer.skip(16);
        }
        getSid().read(buffer);
    }

    @Override
    public String toString() {
        return "AceType2{" +
                "flags=" + flags +
                ", objectType=" + objectType +
                ", inheritedObjectType=" + inheritedObjectType +
                "} " + super.toString();
    }
}
