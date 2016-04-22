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
package com.hierynomus.msdtyp;

import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;
import com.hierynomus.smbj.smb2.SMB2DirectoryAccessMask;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.UUID;

import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toEnumSet;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.valueOf;

/**
 * [MS-DTYP].pdf 2.4.4 ACE
 */
public abstract class ACE {

    static int HEADER_STRUCTURE_SIZE = 4;

    public AceHeader aceHeader = new AceHeader();

    long accessMask;
    private SID sid = new SID();

    public ACE(AceHeader aceHeader, long accessMask, SID sid) {
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
                ace = new AccessAllowedAce().read(buffer);
                break;
            case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                ace = new AccessAllowedCallbackAce().read(buffer);
                break;
            case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                ace = new AccessAllowedCallbackObjectAce().read(buffer);
                break;
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                ace = new AccessAllowedObjectAce().read(buffer);
                break;
            case ACCESS_DENIED_ACE_TYPE:
                ace = new AccessDeniedAce().read(buffer);
                break;
            case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                ace = new AccessAllowedCallbackAce().read(buffer);
                break;
            case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                ace = new AccessDeniedCallbackObjectAce().read(buffer);
                break;
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                ace = new AccessDeniedObjectAce().read(buffer);
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                ace = new SystemAuditAce().read(buffer);
                break;
            case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                ace = new SystemAuditCallbackAce().read(buffer);
                break;
            case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                ace = new SystemAuditCallbackObjectAce().read(buffer);
                break;
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                ace = new SystemAuditAce().read(buffer);
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                ace = new SystemMandatoryLabelAce().read(buffer);
                break;
            case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                ace = new SystemResourceAttributeAce().read(buffer);
                break;
            case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                ace = new SystemScopedPolicyIdAce().read(buffer);
                break;
            default:
                throw new RuntimeException("Reserved for future use");
        }

        return ace;
    }

    @Override
    public String toString() {
        return "ACE{" +
                "aceHeader=" + aceHeader +
                ", accessMask=" + EnumWithValue.EnumUtils.toEnumSet(accessMask, SMB2DirectoryAccessMask.class) +
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

    public static class AceHeader {


        private AceType aceType;
        private EnumSet<AceFlags> aceFlags;
        private int aceSize;

        public AceHeader() {
        }

        public AceHeader(AceType aceType, EnumSet<AceFlags> aceFlags, int aceSize) {
            this.aceType = aceType;
            this.aceFlags = aceFlags;
            this.aceSize = aceSize;
        }

        public void writeTo(SMBBuffer buffer) {
            buffer.putByte((byte) aceType.getValue());
            buffer.putByte((byte) EnumWithValue.EnumUtils.toLong(aceFlags));
            buffer.putUInt16(aceSize);
        }

        public void readFrom(SMBBuffer buffer) throws Buffer.BufferException {
            this.aceType = valueOf(buffer.readByte(), AceType.class, null);
            this.aceFlags = toEnumSet(buffer.readByte(), AceFlags.class);
            this.aceSize = buffer.readUInt16();
        }

        public int getAceSize() {
            return aceSize;
        }

        public void setAceSize(int aceSize) {
            this.aceSize = aceSize;
        }

        @Override
        public String toString() {
            return "AceHeader{" +
                    "aceType=" + aceType +
                    ", aceFlags=" + aceFlags +
                    ", aceSize=" + aceSize +
                    '}';
        }
    }

    public enum AceType implements EnumWithValue<AceType> {
        ACCESS_ALLOWED_ACE_TYPE(0x00L),
        ACCESS_DENIED_ACE_TYPE(0x01L),
        SYSTEM_AUDIT_ACE_TYPE(0x02L),
        SYSTEM_ALARM_ACE_TYPE(0x03L),
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE(0x04L),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE(0x05L),
        ACCESS_DENIED_OBJECT_ACE_TYPE(0x06L),
        SYSTEM_AUDIT_OBJECT_ACE_TYPE(0x07L),
        SYSTEM_ALARM_OBJECT_ACE_TYPE(0x08L),
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE(0x09L),
        ACCESS_DENIED_CALLBACK_ACE_TYPE(0x0AL),
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE(0x0BL),
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE(0x0CL),
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE(0x0DL),
        SYSTEM_ALARM_CALLBACK_ACE_TYPE(0x0EL),
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE(0x0FL),
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE(0x10L),
        SYSTEM_MANDATORY_LABEL_ACE_TYPE(0x11L),
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE(0x12L),
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE(0x13L);

        private long value;

        AceType(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

    public enum AceFlags implements EnumWithValue<AceFlags> {
        CONTAINER_INHERIT_ACE(0x02L),
        FAILED_ACCESS_ACE_FLAG(0x80L),
        INHERIT_ONLY_ACE(0x08L),
        INHERITED_ACE(0x10L),
        NO_PROPAGATE_INHERIT_ACE(0x04L),
        OBJECT_INHERIT_ACE(0x01L),
        SUCCESSFUL_ACCESS_ACE_FLAG(0x40L);

        private long value;

        AceFlags(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

    public enum AceObjectAccessMask implements EnumWithValue<AceObjectAccessMask> {
        // Object Access Mask
        ADS_RIGHT_DS_CONTROL_ACCESS(0X00000100L),
        ADS_RIGHT_DS_CREATE_CHILD(0X00000001L),
        ADS_RIGHT_DS_DELETE_CHILD(0X00000002L),
        ADS_RIGHT_DS_READ_PROP(0x00000010L),
        ADS_RIGHT_DS_WRITE_PROP(0x00000020L),
        ADS_RIGHT_DS_SELF(0x00000008);


        private long value;

        AceObjectAccessMask(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

    public enum AceObjectFlags implements EnumWithValue<AceObjectFlags> {

        NONE(0x00000001L),
        ACE_OBJECT_TYPE_PRESENT(0x00000001L),
        ACE_INHERITED_OBJECT_TYPE_PRESENT(0x00000002L);


        private long value;

        AceObjectFlags(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }


}

// Since a lot of the ACE type structures share similar structure
// Create some generic structures which can be inherited from

// Type 1 - Header/Mask/SID (ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE, SYSTEM_AUDIT_ACE, SYSTEM_MANDATORY_LABEL_ACE,
// SYSTEM_SCOPED_POLICY_ID_ACE
class AceType1 extends ACE {
    public AceType1() {
    }
    public AceType1(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + sid.byteCount()),
                toLong(accessMask), sid);
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        getSid().write(buffer);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();
        getSid().read(buffer);
    }


}

// Type 2 - Header/Mask/Flags/ObjectType/InheritedObjectType/SID
// (ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE)
class AceType2Object extends ACE {
    EnumSet<AceObjectFlags> flags;
    UUID objectType;
    UUID inheritedObjectType;

    public AceType2Object(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
                          EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType, SID sid) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + 4 + 16 + 16 + sid.byteCount()),
                toLong(accessMask), sid);
        this.flags = flags;
        this.objectType = objectType;
        this.inheritedObjectType = inheritedObjectType;
    }

    AceType2Object() {
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
        return "AceType2Object{" +
                "flags=" + flags +
                ", objectType=" + objectType +
                ", inheritedObjectType=" + inheritedObjectType +
                "} " + super.toString();
    }
}

// Type 3 - Header/Mask/SID/ApplicationData
// (ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_ACE)
class AceType3 extends ACE {

    private byte[] applicationData;

    public AceType3() {
    }

    public AceType3(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid, byte[]
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

// Type 4 - Header/Mask/Flags/ObjectType/InheritedObjectType/Sid/ApplicationData
// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE,
// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
class AceType4 extends AceType2Object {

    private byte[] applicationData;

    public AceType4() {
    }

    public AceType4(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
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
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
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

class AccessAllowedAce extends AceType1 {
    public AccessAllowedAce() {
    }
    public AccessAllowedAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(AceType.ACCESS_ALLOWED_ACE_TYPE, aceFlags, accessMask, sid);
    }
}

class AccessDeniedAce extends AceType1 {
    public AccessDeniedAce() {
    }

    public AccessDeniedAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(AceType.ACCESS_DENIED_ACE_TYPE, aceFlags, accessMask, sid);
    }
}

class SystemAuditAce extends AceType1 {
    public SystemAuditAce() {
    }

    public SystemAuditAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(AceType.SYSTEM_AUDIT_ACE_TYPE, aceFlags, accessMask, sid);
    }
}

class SystemMandatoryLabelAce extends AceType1 {
    public SystemMandatoryLabelAce() {
    }

    public SystemMandatoryLabelAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE, aceFlags, accessMask, sid);
    }
}

class SystemScopedPolicyIdAce extends AceType1 {
    public SystemScopedPolicyIdAce() {
    }

    public SystemScopedPolicyIdAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        super(AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE, aceFlags, accessMask, sid);
    }
}

class AccessAllowedObjectAce extends AceType2Object {

    public AccessAllowedObjectAce() {
    }

    public AccessAllowedObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask>
            accessMask, EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType, SID sid) {
        super(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid);
    }
}

class AccessDeniedObjectAce extends AceType2Object {

    public AccessDeniedObjectAce() {
    }

    public AccessDeniedObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask>
            accessMask, EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType, SID sid) {
        super(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid);
    }
}

class AccessAllowedCallbackAce extends AceType3 {

    public AccessAllowedCallbackAce() {
    }

    public AccessAllowedCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                    SID sid, byte[] applicationData) {
        super(AceType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }
}

class AccessDeniedCallbackAce extends AceType3 {

    public AccessDeniedCallbackAce() {
    }

    public AccessDeniedCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                   SID sid, byte[] applicationData) {
        super(AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }
}

class SystemAuditCallbackAce extends AceType3 {

    public SystemAuditCallbackAce() {
    }

    public SystemAuditCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                  SID sid, byte[] applicationData) {
        super(AceType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }
}

class AccessAllowedCallbackObjectAce extends AceType4 {

    public AccessAllowedCallbackObjectAce() {
    }

    public AccessAllowedCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
                                          EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                          SID sid, byte[] applicationData) {
        super(AceType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid, applicationData);


    }
}

class AccessDeniedCallbackObjectAce extends AceType4 {

    public AccessDeniedCallbackObjectAce() {
    }

    public AccessDeniedCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
                                         EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                         SID sid, byte[] applicationData) {
        super(AceType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid, applicationData);
    }
}

class SystemAuditObjectAce extends AceType4 {

    public SystemAuditObjectAce() {
    }

    public SystemAuditObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
                                EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                SID sid, byte[] applicationData) {
        super(AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid, applicationData);
    }
}

class SystemAuditCallbackObjectAce extends AceType4 {

    public SystemAuditCallbackObjectAce() {
    }

    public SystemAuditCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AceObjectAccessMask> accessMask,
                                EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                SID sid, byte[] applicationData) {
        super(AceType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, aceFlags, accessMask, flags, objectType,
                inheritedObjectType, sid, applicationData);
    }
}

class SystemResourceAttributeAce extends ACE {

    private byte[] attributeData;

    public SystemResourceAttributeAce() {
    }

    public SystemResourceAttributeAce(AceType aceType, EnumSet<AceFlags> aceFlags, EnumSet<AccessMask>
            accessMask, SID sid, byte[] attributeData) {
        super(new AceHeader(aceType, aceFlags, ACE.HEADER_STRUCTURE_SIZE + 4 + 4 + sid.byteCount() +
                        attributeData.length),
                toLong(accessMask), sid);
        this.attributeData = attributeData;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt32(accessMask);
        getSid().write(buffer);
        buffer.putRawBytes(attributeData);
    }

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();
        getSid().read(buffer);
        attributeData = buffer.readRawBytes(aceHeader.getAceSize() - 4 + 4 + getSid().byteCount());
    }

}