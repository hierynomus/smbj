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
import com.hierynomus.msdtyp.ace.*;
import com.hierynomus.smbj.common.SMBRuntimeException;

import java.io.IOException;
import java.util.*;

import static com.hierynomus.msdtyp.AccessMask.*;
import static com.hierynomus.msdtyp.ace.AceFlag.*;
import static com.hierynomus.msdtyp.ace.AceType.*;

public final class Sddl {
    private static final Map<String, SddlAclFlags> ACL_FLAGS_FOR_SDDL;
    private static final Map<SddlAclFlags, String> ACL_FLAGS_TO_SDDL;
    private static final Map<String, AceType> ACE_TYPE_FOR_SDDL;
    private static final Map<AceType, String> ACE_TYPE_TO_SDDL;
    private static final Map<String, AceFlag> ACE_FLAG_FOR_SDDL;
    private static final Map<AceFlag, String> ACE_FLAG_TO_SDDL;
    private static final Map<String, String> SIDS_FOR_SDDL;
    private static final Map<String, String> SIDS_TO_SDDL;
    private static final Map<String, Integer> ACE_RIGHTS;

    static {
        ACE_TYPE_FOR_SDDL = new HashMap<>();
        ACE_TYPE_FOR_SDDL.put("A", ACCESS_ALLOWED_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("D", ACCESS_DENIED_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("OA", ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("OD", ACCESS_DENIED_OBJECT_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("AU", SYSTEM_AUDIT_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("OU", SYSTEM_AUDIT_OBJECT_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("ML", SYSTEM_MANDATORY_LABEL_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("SP", SYSTEM_SCOPED_POLICY_ID_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("XA", ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("XD", ACCESS_DENIED_CALLBACK_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("ZA", SYSTEM_AUDIT_CALLBACK_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("XU", ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE);
        ACE_TYPE_FOR_SDDL.put("RA", SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);

        ACE_TYPE_TO_SDDL = inverse(ACE_TYPE_FOR_SDDL);

        int standardAll = (int) (DELETE.getValue() | READ_CONTROL.getValue() | WRITE_DAC.getValue() | WRITE_OWNER.getValue() | SYNCHRONIZE.getValue());

        int fa = standardAll | 0x1FF;
        int fr = (int) (READ_CONTROL.getValue() | FILE_READ_DATA.getValue() | FILE_READ_ATTRIBUTES.getValue() | FILE_READ_EA.getValue() | SYNCHRONIZE.getValue());
        int fw = (int) (READ_CONTROL.getValue() | FILE_WRITE_DATA.getValue() | FILE_WRITE_ATTRIBUTES.getValue() | FILE_WRITE_EA.getValue() | FILE_APPEND_DATA.getValue() | SYNCHRONIZE.getValue());
        int fx = (int) (READ_CONTROL.getValue() | FILE_READ_ATTRIBUTES.getValue() | FILE_TRAVERSE.getValue() | SYNCHRONIZE.getValue());

        ACE_RIGHTS = new HashMap<>();
        ACE_RIGHTS.put("GA", (int) GENERIC_ALL.getValue());
        ACE_RIGHTS.put("GR", (int) GENERIC_READ.getValue());
        ACE_RIGHTS.put("GW", (int) GENERIC_WRITE.getValue());
        ACE_RIGHTS.put("GX", (int) GENERIC_EXECUTE.getValue());
        ACE_RIGHTS.put("WO", (int) WRITE_OWNER.getValue());
        ACE_RIGHTS.put("WD", (int) WRITE_DAC.getValue());
        ACE_RIGHTS.put("RC", (int) READ_CONTROL.getValue());
        ACE_RIGHTS.put("SD", (int) DELETE.getValue());
        ACE_RIGHTS.put("FA", fa);
        ACE_RIGHTS.put("FR", fr);
        ACE_RIGHTS.put("FW", fw);
        ACE_RIGHTS.put("FX", fx);
        ACE_RIGHTS.put("KA", 0x00000019);
        ACE_RIGHTS.put("KR", 0x20019);
        ACE_RIGHTS.put("KW", 0x20006);
        ACE_RIGHTS.put("KX", 0x20019);
        ACE_RIGHTS.put("CR", (int) ADS_RIGHT_DS_CONTROL_ACCESS.getValue());
        ACE_RIGHTS.put("LO", 0x00000080);
        ACE_RIGHTS.put("DT", 0x00000040);
        ACE_RIGHTS.put("WP", (int) ADS_RIGHT_DS_WRITE_PROP.getValue());
        ACE_RIGHTS.put("RP", (int) ADS_RIGHT_DS_READ_PROP.getValue());
        ACE_RIGHTS.put("SW", (int) ADS_RIGHT_DS_SELF.getValue());
        ACE_RIGHTS.put("LC", 0x00000004);
        ACE_RIGHTS.put("DC", (int) ADS_RIGHT_DS_DELETE_CHILD.getValue());
        ACE_RIGHTS.put("CC", (int) ADS_RIGHT_DS_CREATE_CHILD.getValue());
        ACE_RIGHTS.put("NR", 0x00000002);
        ACE_RIGHTS.put("NW", 0x00000001);
        ACE_RIGHTS.put("NX", 0x00000004);

        ACE_FLAG_FOR_SDDL = new HashMap<>();
        ACE_FLAG_FOR_SDDL.put("CI", CONTAINER_INHERIT_ACE);
        ACE_FLAG_FOR_SDDL.put("OI", OBJECT_INHERIT_ACE);
        ACE_FLAG_FOR_SDDL.put("NP", NO_PROPAGATE_INHERIT_ACE);
        ACE_FLAG_FOR_SDDL.put("IO", INHERIT_ONLY_ACE);
        ACE_FLAG_FOR_SDDL.put("ID", INHERITED_ACE);
        ACE_FLAG_FOR_SDDL.put("SA", SUCCESSFUL_ACCESS_ACE_FLAG);
        ACE_FLAG_FOR_SDDL.put("FA", FAILED_ACCESS_ACE_FLAG);

        ACE_FLAG_TO_SDDL = inverse(ACE_FLAG_FOR_SDDL);

        ACL_FLAGS_FOR_SDDL = new HashMap<>();
        ACL_FLAGS_FOR_SDDL.put("P", SddlAclFlags.PROTECTED);
        ACL_FLAGS_FOR_SDDL.put("AI", SddlAclFlags.AUTO_INHERITED);
        ACL_FLAGS_FOR_SDDL.put("AR", SddlAclFlags.AUTO_INHERITANCE_REQUIRED);
        ACL_FLAGS_FOR_SDDL.put("NO_ACCESS_CONTROL", SddlAclFlags.NO_ACL);

        ACL_FLAGS_TO_SDDL = inverse(ACL_FLAGS_FOR_SDDL);

        SIDS_FOR_SDDL = new HashMap<>();
        SIDS_FOR_SDDL.put("AA", "S-1-5-32-579");
        SIDS_FOR_SDDL.put("AC", "S-1-15-2-1");
        SIDS_FOR_SDDL.put("AN", "S-1-5-7");
        SIDS_FOR_SDDL.put("AO", "S-1-5-32-548");
        SIDS_FOR_SDDL.put("AP", null); // S-1-5-21-x-y-z-525
        SIDS_FOR_SDDL.put("AS", "S-1-18-1");
        SIDS_FOR_SDDL.put("AU", "S-1-5-11");
        SIDS_FOR_SDDL.put("BA", "S-1-5-32-544");
        SIDS_FOR_SDDL.put("BG", "S-1-5-32-546");
        SIDS_FOR_SDDL.put("BO", "S-1-5-32-551");
        SIDS_FOR_SDDL.put("BU", "S-1-5-32-545");
        SIDS_FOR_SDDL.put("CA", null); // S-1-5-21-x-y-z-517
        SIDS_FOR_SDDL.put("CD", "S-1-5-32-574");
        SIDS_FOR_SDDL.put("CG", "S-1-3-1");
        SIDS_FOR_SDDL.put("CO", "S-1-3-0");
        SIDS_FOR_SDDL.put("CN", null); // S-1-5-21-x-y-z-522
        SIDS_FOR_SDDL.put("CY", "S-1-5-32-569");
        SIDS_FOR_SDDL.put("DA", null); // S-1-5-21-x-y-z-512
        SIDS_FOR_SDDL.put("DC", null); // S-1-5-21-x-y-z-515
        SIDS_FOR_SDDL.put("DD", null); // S-1-5-21-x-y-z-516
        SIDS_FOR_SDDL.put("DG", null); // S-1-5-21-x-y-z-514
        SIDS_FOR_SDDL.put("DU", null); // S-1-5-21-x-y-z-513
        SIDS_FOR_SDDL.put("EA", null); // S-1-5-21-x-y-z-519
        SIDS_FOR_SDDL.put("ED", "S-1-5-9");
        SIDS_FOR_SDDL.put("ER", "S-1-5-32-573");
        SIDS_FOR_SDDL.put("ES", "S-1-5-32-576");
        SIDS_FOR_SDDL.put("HA", "S-1-5-32-578");
        SIDS_FOR_SDDL.put("HI", "S-1-16-12288");
        SIDS_FOR_SDDL.put("IS", "S-1-5-32-568");
        SIDS_FOR_SDDL.put("IU", "S-1-5-4");
        SIDS_FOR_SDDL.put("LA", null); // S-1-5-21-x-y-z-500
        SIDS_FOR_SDDL.put("LG", null); // S-1-5-21-x-y-z-501
        SIDS_FOR_SDDL.put("LS", "S-1-5-19");
        SIDS_FOR_SDDL.put("LU", "S-1-5-32-559");
        SIDS_FOR_SDDL.put("LW", "S-1-16-4096");
        SIDS_FOR_SDDL.put("ME", "S-1-16-8192");
        SIDS_FOR_SDDL.put("MP", "S-1-16-8448");
        SIDS_FOR_SDDL.put("MS", "S-1-5-32-577");
        SIDS_FOR_SDDL.put("MU", "S-1-5-32-558");
        SIDS_FOR_SDDL.put("NO", "S-1-5-32-556");
        SIDS_FOR_SDDL.put("NS", "S-1-5-20");
        SIDS_FOR_SDDL.put("NU", "S-1-5-2");
        SIDS_FOR_SDDL.put("OW", "S-1-3-4");
        SIDS_FOR_SDDL.put("PA", null); // S-1-5-21-x-y-z-520
        SIDS_FOR_SDDL.put("PO", "S-1-5-32-550");
        SIDS_FOR_SDDL.put("PS", "S-1-5-10");
        SIDS_FOR_SDDL.put("PU", "S-1-5-32-547");
        SIDS_FOR_SDDL.put("RA", "S-1-5-32-575");
        SIDS_FOR_SDDL.put("RC", "S-1-5-12");
        SIDS_FOR_SDDL.put("RD", "S-1-5-32-555");
        SIDS_FOR_SDDL.put("RE", "S-1-5-32-552");
        SIDS_FOR_SDDL.put("RM", "S-1-5-32-580");
        SIDS_FOR_SDDL.put("RO", null); // S-1-5-21-x-y-z-498
        SIDS_FOR_SDDL.put("RS", null); // S-1-5-21-x-y-z-553
        SIDS_FOR_SDDL.put("RU", "S-1-5-32-554");
        SIDS_FOR_SDDL.put("SA", null); // S-1-5-21-x-y-z-518
        SIDS_FOR_SDDL.put("SI", "S-1-16-16384");
        SIDS_FOR_SDDL.put("SO", "S-1-5-32-549");
        SIDS_FOR_SDDL.put("SS", "S-1-18-2");
        SIDS_FOR_SDDL.put("SU", "S-1-5-6");
        SIDS_FOR_SDDL.put("SY", "S-1-5-18");
        SIDS_FOR_SDDL.put("UD", "S-1-5-84-0-0-0-0-0");
        SIDS_FOR_SDDL.put("WD", "S-1-1-0");
        SIDS_FOR_SDDL.put("WR", "S-1-5-33");

        SIDS_TO_SDDL = inverse(SIDS_FOR_SDDL);
    }

    private static <K, V> Map<V, K> inverse(Map<K, V> map) {
        Map<V, K> inverse = new HashMap<>();
        for (Map.Entry<K, V> entry : map.entrySet()) {
            if (entry.getValue() != null) {
                inverse.put(entry.getValue(), entry.getKey());
            }
        }
        return inverse;
    }

    private Sddl() {
    }

    static SddlAclFlags aclFlagFromSddl(String text) {
        return ACL_FLAGS_FOR_SDDL.get(text);
    }

    private static String aclFlagToSddl(SddlAclFlags flag) {
        return ACL_FLAGS_TO_SDDL.get(flag);
    }

    static AceType aceTypeFromSddl(String txt) {
        return ACE_TYPE_FOR_SDDL.get(txt);
    }

    private static String aceTypeToSddl(AceType type) {
        return ACE_TYPE_TO_SDDL.get(type);
    }

    static AceFlag aceFlagFromSddl(String text) {
        return ACE_FLAG_FOR_SDDL.get(text);
    }

    private static String aceFlagToSddl(AceFlag flag) {
        return ACE_FLAG_TO_SDDL.get(flag);
    }

    static long aceRightFromSddl(String txt) {
        return ACE_RIGHTS.get(txt);
    }

    static String resolveSidLiteral(String sidLiteral) {
        if (SIDS_FOR_SDDL.containsKey(sidLiteral)) {
            String value = SIDS_FOR_SDDL.get(sidLiteral);
            if (value == null) {
                throw new SMBRuntimeException("SID token " + sidLiteral + " is not supported");
            }
            return value;
        } else {
            return sidLiteral;
        }
    }

    public static SecurityDescriptor parse(String sddl) throws IOException {
        SddlParser parser = new SddlParser();
        parser.parse(new SourceString(sddl));
        return parser.semantics().getResult();
    }

    public static String format(SecurityDescriptor sd) throws IOException {
        StringBuilder b = new StringBuilder();

        formatOwner(b, sd.getOwnerSid());
        formatGroup(b, sd.getGroupSid());
        formatDacl(b, sd.getDacl(), sd.getControl());
        formatSacl(b, sd.getSacl(), sd.getControl());

        return b.toString();
    }

    private static void formatOwner(StringBuilder b, SID ownerSid) {
        if (ownerSid != null) {
            b.append("O:");
            b.append(ownerSid);
        }
    }

    private static void formatGroup(StringBuilder b, SID groupSid) {
        if (groupSid != null) {
            b.append("G:");
            b.append(groupSid);
        }
    }

    private static void formatDacl(StringBuilder b, ACL dacl, EnumSet<SecurityDescriptor.Control> control) {
        if (control.contains(SecurityDescriptor.Control.DP)) {
            b.append("D:");

            Set<SddlAclFlags> flags = EnumSet.noneOf(SddlAclFlags.class);
            if (control.contains(SecurityDescriptor.Control.PD)) {
                flags.add(SddlAclFlags.PROTECTED);
            }
            if (control.contains(SecurityDescriptor.Control.DI)) {
                flags.add(SddlAclFlags.AUTO_INHERITED);
            }
            if (control.contains(SecurityDescriptor.Control.DC)) {
                flags.add(SddlAclFlags.AUTO_INHERITANCE_REQUIRED);
            }
            if (dacl == null) {
                flags.add(SddlAclFlags.NO_ACL);
            }

            format(b, dacl, flags);
        }
    }

    private static void formatSacl(StringBuilder b, ACL sacl, EnumSet<SecurityDescriptor.Control> control) {
        if (control.contains(SecurityDescriptor.Control.SP)) {
            b.append("S:");

            Set<SddlAclFlags> flags = EnumSet.noneOf(SddlAclFlags.class);
            if (control.contains(SecurityDescriptor.Control.PS)) {
                flags.add(SddlAclFlags.PROTECTED);
            }
            if (control.contains(SecurityDescriptor.Control.SI)) {
                flags.add(SddlAclFlags.AUTO_INHERITED);
            }
            if (control.contains(SecurityDescriptor.Control.SC)) {
                flags.add(SddlAclFlags.AUTO_INHERITANCE_REQUIRED);
            }
            if (sacl == null) {
                flags.add(SddlAclFlags.NO_ACL);
            }

            format(b, sacl, flags);
        }
    }

    private static void format(StringBuilder b, ACL acl, Set<SddlAclFlags> aclFlags) {
        for (SddlAclFlags flag : aclFlags) {
            b.append(aclFlagToSddl(flag));
        }

        if (acl != null) {
            for (Ace ace : acl.getAces()) {
                format(b, ace);
            }
        }
    }

    private static void format(StringBuilder b, Ace ace) {
        UUID guid = getObjectType(ace);
        UUID inhertedGuid = getInheritedObjectType(ace);
        String expression = getExpression(ace);

        b.append('(');
        b.append(aceTypeToSddl(ace.getAceHeader().getAceType()));
        b.append(";");
        for (AceFlag flag : ace.getAceHeader().getAceFlags()) {
            b.append(aceFlagToSddl(flag));
        }
        b.append(";");
        long accessMask = ace.getAccessMask();
        if (accessMask != 0) {
            formatAccessMask(b, accessMask);
        }
        b.append(";");
        if (guid != null) {
            b.append(guid);
        }
        b.append(";");
        if (inhertedGuid != null) {
            b.append(inhertedGuid);
        }
        b.append(";");
        if (ace.getSid() != null) {
            format(b, ace.getSid());
        }
        if (expression != null) {
            b.append(";(");
            b.append(expression);
            b.append(")");
        }
        b.append(')');
    }

    private static UUID getObjectType(Ace ace) {
        if (ace instanceof ObjectAce) {
            return ((ObjectAce) ace).getObjectType();
        } else {
            return null;
        }
    }

    private static UUID getInheritedObjectType(Ace ace) {
        if (ace instanceof ObjectAce) {
            return ((ObjectAce) ace).getInheritedObjectType();
        } else {
            return null;
        }
    }

    private static String getExpression(Ace ace) {
        if (ace instanceof CallbackAce) {
            byte[] applicationData = ((CallbackAce) ace).getApplicationData();
            if (applicationData == null) {
                return "";
            } else {
                throw new SMBRuntimeException("Formatting of callback application data is not supported");
            }
        } else if (ace instanceof ObjectCallbackAce) {
            byte[] applicationData = ((ObjectCallbackAce) ace).getApplicationData();
            if (applicationData == null) {
                return "";
            } else {
                throw new SMBRuntimeException("Formatting of object callback application data is not supported");
            }
        } else {
            return null;
        }
    }

    private static void format(StringBuilder b, SID sid) {
        String sidLiteral = sid.toString();
        String sidToken = SIDS_TO_SDDL.get(sidLiteral);
        b.append(sidToken != null ? sidToken : sidLiteral);
    }

    private static void formatAccessMask(StringBuilder b, long accessMask) {
        // TODO try to generate SDDL abbreviations?
        b.append("0x");
        b.append(Long.toString(accessMask, 16));
    }
}
