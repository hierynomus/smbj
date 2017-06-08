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

    public SecurityDescriptor(EnumSet<Control> control, SID ownerSid, SID groupSid, ACL sacl, ACL dacl) {
        this.control = control;
        this.ownerSid = ownerSid;
        this.groupSid = groupSid;
        this.sacl = sacl;
        this.dacl = dacl;
    }

    public void write(SMBBuffer buffer) {
        int startPos = buffer.wpos();
        buffer.putByte((byte)1); // Revision (1 byte)
        buffer.putByte((byte)0); // Sbz1 (1 byte)

        EnumSet<Control> c = EnumSet.copyOf(control);
        // Always generate self-relative security descriptors; required for SMB
        c.add(Control.SR);
        if (sacl != null) {
            c.add(Control.SP);
        }
        if (dacl != null) {
            c.add(Control.DP);
        }

        buffer.putUInt16((int) EnumWithValue.EnumUtils.toLong(control)); // Control (2 bytes)

        int offsetsPos = buffer.wpos();
        buffer.putUInt32(0);
        buffer.putUInt32(0);
        buffer.putUInt32(0);
        buffer.putUInt32(0);

        int ownerOffset;
        if (ownerSid != null) {
            ownerOffset = buffer.wpos() - startPos;
            ownerSid.write(buffer);
        } else {
            ownerOffset = 0;
        }
        int groupOffset;
        if (groupSid != null) {
            groupOffset = buffer.wpos() - startPos;
            groupSid.write(buffer);
        } else {
            groupOffset = 0;
        }
        int saclOffset;
        if (sacl != null) {
            saclOffset = buffer.wpos() - startPos;
            sacl.write(buffer);
        } else {
            saclOffset = 0;
        }
        int daclOffset;
        if (dacl != null) {
            daclOffset = buffer.wpos() - startPos;
            dacl.write(buffer);
        } else {
            daclOffset = 0;
        }

        int endPos = buffer.wpos();
        buffer.wpos(offsetsPos);
        buffer.putUInt32(ownerOffset);
        buffer.putUInt32(groupOffset);
        buffer.putUInt32(saclOffset);
        buffer.putUInt32(daclOffset);
        buffer.wpos(endPos);
    }

    public static SecurityDescriptor read(SMBBuffer buffer) throws Buffer.BufferException {
        int startPos = buffer.rpos();

        buffer.readByte(); // Revision
        buffer.readByte(); // Sbz1
        EnumSet<Control> control = EnumWithValue.EnumUtils.toEnumSet(buffer.readUInt16(), Control.class);
        int ownerOffset = buffer.readUInt32AsInt();
        int groupOffset = buffer.readUInt32AsInt();
        int saclOffset = buffer.readUInt32AsInt();
        int daclOffset = buffer.readUInt32AsInt();

        SID ownerSid = null;
        if (ownerOffset > 0) {
            buffer.rpos(startPos + ownerOffset);
            ownerSid = SID.read(buffer);
        }
        SID groupSid = null;
        if (groupOffset > 0) {
            buffer.rpos(startPos + groupOffset);
            groupSid = SID.read(buffer);
        }
        ACL sacl = null;
        if (saclOffset > 0) {
            buffer.rpos(startPos + saclOffset);
            sacl = ACL.read(buffer);
        }
        ACL dacl = null;
        if (daclOffset > 0) {
            buffer.rpos(startPos + daclOffset);
            dacl = ACL.read(buffer);
        }
        return new SecurityDescriptor(control, ownerSid, groupSid, sacl, dacl);
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
        NONE(0x0000),
        // Self-relative
        SR(0x8000),
        // RM Control valid
        RM(0x4000),
        // SACL protected
        PS(0x2000),
        // DACL protected
        PD(0x1000),
        // SACL auto-inherited
        SI(0x0800),
        // DACL auto-inherited
        DI(0x0400),
        // SACL computed inheritance required
        SC(0x0200),
        // DACL computed inheritance required
        DC(0x0100),
        // DACL trusted
        DT(0x0080),
        // Server Security
        SS(0x0040),
        // SACL defaulted
        SD(0x0020),
        // SACL present
        SP(0x0010),
        // DACL defaulted
        DD(0x0008),
        // DACL present
        DP(0x0004),
        // Group defaulted
        GD(0x0002),
        // Owner defaulted
        OD(0x0001);

        private long value;

        Control(long value) {
            this.value = value;
        }

        public long getValue() {
            return value;
        }
    }

}
