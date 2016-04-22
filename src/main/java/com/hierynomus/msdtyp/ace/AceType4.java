package com.hierynomus.msdtyp.ace;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.UUID;

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
