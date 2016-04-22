package com.hierynomus.msdtyp.ace;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smbj.common.SMBBuffer;

import java.util.EnumSet;

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
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        accessMask = buffer.readUInt32();
        getSid().read(buffer);
    }


}
