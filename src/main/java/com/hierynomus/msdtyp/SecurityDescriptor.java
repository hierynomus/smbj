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
import com.hierynomus.smbj.smb2.SMB2Header;
import com.hierynomus.smbj.smb2.messages.SMB2SetInfoRequest;

import java.util.EnumSet;

/**
 * [MS-DTYP].pdf 2.4.6 SecurityDescriptor
 */
public class SecurityDescriptor {

    private EnumSet<Control> control;
    private SID ownerSid;
    private SID groupSid;
    private ACL sacl;
    private ACL dacl;

    public SecurityDescriptor() {
    }

    public SecurityDescriptor(EnumSet<Control> control, SID ownerSid, SID groupSid, ACL sacl, ACL dacl) {
        this.control = control;
        this.ownerSid = ownerSid;
        this.groupSid = groupSid;
        this.sacl = sacl;
        this.dacl = dacl;
    }

    public void write(SMBBuffer buffer) {
        buffer.putByte((byte)1); // Revision (1 byte)
        buffer.putByte((byte)0); // Sbz1 (1 byte)
        buffer.putUInt16((int) EnumWithValue.EnumUtils.toLong(control)); // Control (2 bytes)
        int offset = SMB2Header.STRUCTURE_SIZE + 20;
        if (ownerSid != null) {
            buffer.putUInt32(offset);
            offset += ownerSid.byteCount();
        }
        if (groupSid != null) {
            buffer.putUInt32(offset);
            offset += groupSid.byteCount();
        }
        if (sacl != null) {
            sacl.write(buffer);
            offset += sacl.aclSize;
        }
        if (dacl != null) {
            dacl.write(buffer);
            offset += dacl.aclSize;
        }
    }

    public void read(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readByte(); // Revision
        buffer.readByte(); // Sbz1
        control = EnumWithValue.EnumUtils.toEnumSet(buffer.readUInt16(), Control.class);
        int ownerOffset = buffer.readUInt32AsInt();
        int groupOffset = buffer.readUInt32AsInt();
        int saslOffset = buffer.readUInt32AsInt();
        int daslOffset = buffer.readUInt32AsInt();

        if (ownerOffset > 0) {
            buffer.rpos(ownerOffset);
            ownerSid = new SID();
            ownerSid.read(buffer);
        }
        if (groupOffset > 0) {
            buffer.rpos(groupOffset);
            groupSid = new SID();
            groupSid.read(buffer);
        }
        if (saslOffset > 0) {
            buffer.rpos(saslOffset);
            sacl = new ACL();
            sacl.read(buffer);
        }
        if (daslOffset > 0) {
            buffer.rpos(daslOffset);
            dacl = new ACL();
            dacl.read(buffer);
        }
    }

    public EnumSet<Control> getControl() {
        return control;
    }

    public SID getOwnerSid() {
        return ownerSid;
    }

    public SID getGroupSid() {
        return groupSid;
    }

    public ACL getSacl() {
        return sacl;
    }

    public ACL getDacl() {
        return dacl;
    }

    @Override
    public String toString() {
        return "SecurityDescriptor{" +
                "control=" + control +
                ", ownerSid=" + ownerSid +
                ", groupSid=" + groupSid +
                ", sacl=" + sacl +
                ", dacl=" + dacl +
                '}';
    }

    // SecurityDescriptor Control bits
    public enum Control implements EnumWithValue<Control> {
        NONE(0x00000000L),
        SR(0x00000001L),
        RM(0x00000002L),
        PS(0x00000004L),
        PD(0x00000008L),
        SI(0x00000010L),
        DI(0x00000020L),
        SC(0x00000040L),
        DC(0x00000080L),
        DT(0x00000100L),
        SS(0x00000200L),
        SD(0x00000400L),
        SP(0x00000800L),
        DD(0x00001000L),
        DP(0x00002000L),
        GD(0x00004000L),
        OD(0x00008000L)
        ;

        private long value;

        Control(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

}
