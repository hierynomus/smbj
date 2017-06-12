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

package com.hierynomus.msdtyp.sddl;

import com.hierynomus.msdtyp.ACL;
import com.hierynomus.msdtyp.SID;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.ace.Ace;
import com.hierynomus.msdtyp.ace.AceFlag;
import com.hierynomus.msdtyp.ace.AceType;
import com.hierynomus.msdtyp.ace.AceTypes;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.IOException;
import java.util.*;

class SddlParserSemantics extends com.hierynomus.msdtyp.sddl.SemanticsBase {
    private EnumSet<SecurityDescriptor.Control> control;
    private SID ownerSid;
    private SID groupSid;
    private ACL sacl;
    private ACL dacl;

    private String error;
    private SecurityDescriptor securityDescriptor;

    public static SecurityDescriptor parse(String sddl) throws IOException {
        SddlParser parser = new SddlParser();
        parser.parse(new SourceString(sddl));
        return parser.semantics().getResult();
    }

    SddlParserSemantics() {
        control = EnumSet.noneOf(SecurityDescriptor.Control.class);
    }

    SecurityDescriptor getResult() {
        if (error != null) {
            throw new SMBRuntimeException(error);
        } else if (securityDescriptor == null) {
            throw new SMBRuntimeException("Internal SDDL parser error");
        } else {
            return securityDescriptor;
        }
    }

    void error() {
        Phrase lhs = lhs();
        error = lhs.errMsg();
        lhs.errClear();
    }

    void sddl() {
        securityDescriptor = new SecurityDescriptor(control, ownerSid, groupSid, sacl, dacl);
    }

    void owner() {
        ownerSid = (SID) rhs(1).get();
    }

    void group() {
        groupSid = (SID) rhs(1).get();
    }

    void dacl() {
        ACLWithFlags aclWithFlags = (ACLWithFlags) rhs(1).get();
        dacl = aclWithFlags.acl;
        control.add(SecurityDescriptor.Control.DP);

        Set<SddlAclFlags> flags = aclWithFlags.flags;
        if (flags.contains(SddlAclFlags.PROTECTED)) {
            control.add(SecurityDescriptor.Control.PD);
        }
        if (flags.contains(SddlAclFlags.AUTO_INHERITED)) {
            control.add(SecurityDescriptor.Control.DI);
        }
        if (flags.contains(SddlAclFlags.AUTO_INHERITANCE_REQUIRED)) {
            control.add(SecurityDescriptor.Control.DC);
        }
    }

    void sacl() {
        ACLWithFlags aclWithFlags = (ACLWithFlags) rhs(1).get();
        sacl = aclWithFlags.acl;
        control.add(SecurityDescriptor.Control.SP);

        Set<SddlAclFlags> flags = aclWithFlags.flags;
        if (flags.contains(SddlAclFlags.PROTECTED)) {
            control.add(SecurityDescriptor.Control.PS);
        }
        if (flags.contains(SddlAclFlags.AUTO_INHERITED)) {
            control.add(SecurityDescriptor.Control.SI);
        }
        if (flags.contains(SddlAclFlags.AUTO_INHERITANCE_REQUIRED)) {
            control.add(SecurityDescriptor.Control.SC);
        }
    }

    void acl() {
        Set<SddlAclFlags> aclFlags = (Set<SddlAclFlags>) rhs(0).get();
        List<Ace> aces = (List<Ace>) rhs(1).get();

        ACL acl;
        if (aclFlags.contains(SddlAclFlags.NO_ACL)) {
            acl = null;
        } else {
            acl = new ACL(ACL.ACL_REVISION, aces);
        }
        lhs().put(new ACLWithFlags(acl, aclFlags));
    }

    void aclFlags() {
        Set<SddlAclFlags> flags = EnumSet.noneOf(SddlAclFlags.class);
        for (int i = 0; i < rhsSize(); i++) {
            flags.add((SddlAclFlags) rhs(i).get());
        }
        lhs().put(flags);
    }

    void aclFlag() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aclFlagFromSddl(lhs.text()));
    }

    void aces() {
        List<Ace> aces = new ArrayList<>();
        for (int i = 0; i < rhsSize(); i++) {
            aces.add((Ace) rhs(i).get());
        }
        lhs().put(aces);
    }

    void aceType() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aceTypeFromSddl(lhs.text()));
    }

    // "(" AceType ";" AceFlagString ";" AceRights ";" Guid ";" Guid ";" SidString ")"
    void ace() {
        AceType aceType = (AceType) rhs(1).get();
        Set<AceFlag> aceFlags = (Set<AceFlag>) rhs(3).get();
        long accessMask = ((Number) rhs(5).get()).longValue();
        // UUID guid = (UUID) rhs(7).get();
        // UUID inheritObjectGuid = (UUID) rhs(9).get();
        SID sid = (SID) rhs(11).get();

        switch (aceType) {
            case ACCESS_ALLOWED_ACE_TYPE:
                lhs().put(AceTypes.accessAllowedAce(aceFlags, accessMask, sid));
                break;
            case ACCESS_DENIED_ACE_TYPE:
                lhs().put(AceTypes.accessDeniedAce(aceFlags, accessMask, sid));
                break;
            default:
                throw new SMBRuntimeException(lhs().where(0) + ": ACE type " + aceType + " is not yet supported");
        }
    }

    void conditionalAceType() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aceTypeFromSddl(lhs.text()));
    }

    // ConditionalAce = "(" ConditionalAceType ";" AceFlagString ";" AceRights ";" Guid ";" Guid ";" SidString ";" "(" CondExpr ")" ")" {conditionalAce};
    void conditionalAce() {
        throw new SMBRuntimeException(lhs().where(0) + ": conditional ACEs are not yet supported");
    }

    void resourceAttributeAceType() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aceTypeFromSddl(lhs.text()));
    }

    // "(" ResourceAttributeAceType ";" AceFlagString ";;;;" ResourceAttributeAceSid ";(" AttributeData "))"
    void resourceAttributeAce() {
        throw new SMBRuntimeException(lhs().where(0) + ": resource attribute ACEs are not yet supported");
    }

    void aceFlags() {
        Set<AceFlag> flags = EnumSet.noneOf(AceFlag.class);
        for (int i = 0; i < rhsSize(); i++) {
            flags.add((AceFlag) rhs(i).get());
        }
        lhs().put(flags);
    }

    void aceFlag() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aceFlagFromSddl(lhs.text()));
    }

    void guid() {
        if (rhsSize() < 0) {
            lhs().put(UUID.fromString(lhs().text()));
        }
    }

    void sid() {
        String sidLiteral = lhs().text();
        sidLiteral = Sddl.resolveSidLiteral(sidLiteral);

        SID sid = SID.parse(sidLiteral);
        lhs().put(sid);
    }

    void aceRights() {
        if (rhsSize() == 0) {
            lhs().put(0);
        } else {
            lhs().put(rhs(0).get());
        }
    }

    void textRights() {
        long rights = 0;
        for (int i = 0; i < rhsSize(); i++) {
            rights |= ((Number) rhs(i).get()).longValue();
        }
        lhs().put(rights);
    }

    void textRight() {
        Phrase lhs = lhs();
        lhs.put(Sddl.aceRightFromSddl(lhs.text()));
    }

    void uint64() {
        String text = lhs().text();
        lhs().put(parseUInt64(text));
    }

    void int64() {
        long sign = 1L;
        String text = lhs().text();
        if (text.startsWith("+")) {
            text = text.substring(1);
        } else if (text.startsWith("-")) {
            text = text.substring(1);
            sign = -1L;
        }
        lhs().put(sign * parseUInt64(text));
    }

    private long parseUInt64(String text) {
        if (text.startsWith("0x")) {
            return Long.parseLong(text.substring(2), 16);
        } else if (text.startsWith("0")) {
            return Long.parseLong(text.substring(1), 8);
        } else {
            return Long.parseLong(text);
        }
    }

    private static class ACLWithFlags {
        ACL acl;
        Set<SddlAclFlags> flags;

        ACLWithFlags(ACL acl, Set<SddlAclFlags> flags) {
            this.acl = acl;
            this.flags = flags;
        }
    }
}
