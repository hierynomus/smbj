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

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

// Type 2 - Header/Mask/Flags/ObjectType/InheritedObjectType/SID
// (ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE)
class AceType2 extends ACE {
    long accessMask;
    SID sid;
    UUID objectType;
    UUID inheritedObjectType;

    AceType2(AceHeader header) {
        super(header);
    }

    AceType2(AceHeader header, long accessMask, UUID objectType, UUID inheritedObjectType, SID sid) {
        super(header);
        this.accessMask = accessMask;
        this.sid = sid;
        this.objectType = objectType;
        this.inheritedObjectType = inheritedObjectType;
    }

    @Override
    void writeBody(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);

        EnumSet<AceObjectFlags> flags = EnumSet.noneOf(AceObjectFlags.class);
        if (objectType != null) {
            flags.add(AceObjectFlags.ACE_OBJECT_TYPE_PRESENT);
        }
        if (inheritedObjectType != null) {
            flags.add(AceObjectFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT);
        }
        buffer.putUInt32(toLong(flags));

        if (objectType != null) {
            MsDataTypes.putGuid(objectType, buffer);
        } else {
            buffer.putReserved(16);
        }

        if (inheritedObjectType != null) {
            MsDataTypes.putGuid(inheritedObjectType, buffer);
        } else {
            buffer.putReserved(16);
        }

        sid.write(buffer);
    }

    void readBody(SMBBuffer buffer, int aceStartPos) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();

        Set<AceObjectFlags> flags = toEnumSet(buffer.readUInt32(), AceObjectFlags.class);

        objectType = null;
        if (flags.contains(AceObjectFlags.ACE_OBJECT_TYPE_PRESENT)) {
            objectType = MsDataTypes.readGuid(buffer);
        } else {
            buffer.skip(16);
        }

        inheritedObjectType = null;
        if (flags.contains(AceObjectFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
            inheritedObjectType = MsDataTypes.readGuid(buffer);
        } else {
            buffer.skip(16);
        }

        sid = SID.read(buffer);
    }

    static AceType2 read(AceHeader header, SMBBuffer buffer, int aceStartPos) throws Buffer.BufferException {
        AceType2 ace = new AceType2(header);
        ace.readBody(buffer, aceStartPos);
        return ace;
    }

    @Override
    public String toString() {
        return String.format(
            "AceType2{type=%s, flags=%s, access=0x%x, objectType=%s, inheritedObjectType=%s, sid=%s}",
            aceHeader.getAceType(),
            aceHeader.getAceFlags(),
            accessMask,
            objectType,
            inheritedObjectType,
            sid
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

    public UUID getObjectType() {
        return objectType;
    }

    public UUID getInheritedObjectType() {
        return inheritedObjectType;
    }
}
