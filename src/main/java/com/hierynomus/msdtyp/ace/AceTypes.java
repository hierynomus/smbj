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
import java.util.UUID;
import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SID;

import static com.hierynomus.msdtyp.ace.AceType.ACCESS_ALLOWED_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_DENIED_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.ACCESS_DENIED_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_AUDIT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE;
import static com.hierynomus.msdtyp.ace.AceType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE;

/**
 * Factory methods for the different AceType objects.
 */
public class AceTypes {

    private AceTypes() {
    }

    /**
     * [MS-DTYP].pdf 2.4.4.2 ACCESS_ALLOWED_ACE
     */
    public static ACE accessAllowedAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        return new AceType1(ACCESS_ALLOWED_ACE_TYPE, aceFlags, accessMask, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.3 ACCESS_ALLOWED_OBJECT_ACE
     */
    public static ACE accessAllowedObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                             EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                             SID sid) {
        return new AceType2(ACCESS_ALLOWED_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.4 ACCESS_DENIED_ACE
     */
    public static ACE accessDeniedAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        return new AceType1(ACCESS_DENIED_ACE_TYPE, aceFlags, accessMask, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.5 ACCESS_DENIED_OBJECT_ACE
     */
    public static ACE accessDeniedObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                            EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                            SID sid) {
        return new AceType2(ACCESS_DENIED_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.6 ACCESS_ALLOWED_CALLBACK_ACE
     */
    public static ACE accessAllowedCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.7 ACCESS_DENIED_CALLBACK_ACE
     */
    public static ACE accessDeniedCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(ACCESS_DENIED_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.8 ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
     */
    public static ACE accessAllowedCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                                     EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                                     SID sid, byte[] applicationData) {
        return new AceType4(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.9 ACCESS_DENIED_CALLBACK_OBJECT_ACE
     */
    public static ACE accessDeniedCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                                    EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                                    SID sid, byte[] applicationData) {
        return new AceType4(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.10 SYSTEM_AUDIT_ACE
     */
    public static ACE systemAuditAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        return new AceType1(SYSTEM_AUDIT_ACE_TYPE, aceFlags, accessMask, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.11 SYSTEM_AUDIT_OBJECT_ACE
     */
    public static ACE systemAuditObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                           EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                           SID sid, byte[] applicationData) {
        return new AceType4(SYSTEM_AUDIT_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.12 SYSTEM_AUDIT_CALLBACK_ACE
     */
    public static ACE systemAuditCallbackAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, aceFlags, accessMask, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.13 SYSTEM_MANDATORY_LABEL_ACE
     */
    public static ACE systemMandatoryLabelAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask, SID sid) {
        return new AceType1(SYSTEM_MANDATORY_LABEL_ACE_TYPE, aceFlags, accessMask, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.14 SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
     */
    public static ACE systemAuditCallbackObjectAce(EnumSet<AceFlags> aceFlags, EnumSet<AccessMask> accessMask,
                                                   EnumSet<AceObjectFlags> flags, UUID objectType, UUID inheritedObjectType,
                                                   SID sid, byte[] applicationData) {
        return new AceType4(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, aceFlags, accessMask, flags, objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.15 SYSTEM_RESOURCE_ATTRIBUTE_ACE
     */
    public static ACE systemResourceAttributeAce(EnumSet<AceFlags> aceFlags, byte[] attributeData) {
        return new AceType3(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, aceFlags, EnumSet.noneOf(AccessMask.class), SID.EVERYONE, attributeData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.16 SYSTEM_SCOPED_POLICY_ID_ACE
     */
    public static ACE systemScopedPolicyIdAce(EnumSet<AceFlags> aceFlags, SID sid) {
        return new AceType1(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, aceFlags, EnumSet.noneOf(AccessMask.class), sid);
    }
}
