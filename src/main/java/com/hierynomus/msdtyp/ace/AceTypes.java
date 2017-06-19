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
import com.hierynomus.msdtyp.SID;

import java.util.Set;
import java.util.UUID;

import static com.hierynomus.msdtyp.ace.AceType.*;
import static com.hierynomus.protocol.commons.EnumWithValue.EnumUtils.toLong;

/**
 * Factory methods for the different AceType objects.
 */
public class AceTypes {

    private AceTypes() {
    }

    /**
     * [MS-DTYP].pdf 2.4.4.2 ACCESS_ALLOWED_ACE
     */
    public static ACE accessAllowedAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid) {
        return new AceType1(new AceHeader(ACCESS_ALLOWED_ACE_TYPE, aceFlags), toLong(accessMask), sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.3 ACCESS_ALLOWED_OBJECT_ACE
     */
    public static ACE accessAllowedObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                             UUID objectType, UUID inheritedObjectType,
                                             SID sid) {
        return new AceType2(new AceHeader(ACCESS_ALLOWED_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.4 ACCESS_DENIED_ACE
     */
    public static ACE accessDeniedAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid) {
        return new AceType1(new AceHeader(ACCESS_DENIED_ACE_TYPE, aceFlags), toLong(accessMask), sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.5 ACCESS_DENIED_OBJECT_ACE
     */
    public static ACE accessDeniedObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                            UUID objectType, UUID inheritedObjectType,
                                            SID sid) {
        return new AceType2(new AceHeader(ACCESS_DENIED_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.6 ACCESS_ALLOWED_CALLBACK_ACE
     */
    public static ACE accessAllowedCallbackAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(new AceHeader(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, aceFlags), toLong(accessMask), sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.7 ACCESS_DENIED_CALLBACK_ACE
     */
    public static ACE accessDeniedCallbackAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(new AceHeader(ACCESS_DENIED_CALLBACK_ACE_TYPE, aceFlags), toLong(accessMask), sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.8 ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
     */
    public static ACE accessAllowedCallbackObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                                     UUID objectType, UUID inheritedObjectType,
                                                     SID sid, byte[] applicationData) {
        return new AceType4(new AceHeader(ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.9 ACCESS_DENIED_CALLBACK_OBJECT_ACE
     */
    public static ACE accessDeniedCallbackObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                                    UUID objectType, UUID inheritedObjectType,
                                                    SID sid, byte[] applicationData) {
        return new AceType4(new AceHeader(ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.10 SYSTEM_AUDIT_ACE
     */
    public static ACE systemAuditAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid) {
        return new AceType1(new AceHeader(SYSTEM_AUDIT_ACE_TYPE, aceFlags), toLong(accessMask), sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.11 SYSTEM_AUDIT_OBJECT_ACE
     */
    public static ACE systemAuditObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                           UUID objectType, UUID inheritedObjectType,
                                           SID sid, byte[] applicationData) {
        return new AceType4(new AceHeader(SYSTEM_AUDIT_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.12 SYSTEM_AUDIT_CALLBACK_ACE
     */
    public static ACE systemAuditCallbackAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid, byte[] applicationData) {
        return new AceType3(new AceHeader(SYSTEM_AUDIT_CALLBACK_ACE_TYPE, aceFlags), toLong(accessMask), sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.13 SYSTEM_MANDATORY_LABEL_ACE
     */
    public static ACE systemMandatoryLabelAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask, SID sid) {
        return new AceType1(new AceHeader(SYSTEM_MANDATORY_LABEL_ACE_TYPE, aceFlags), toLong(accessMask), sid);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.14 SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
     */
    public static ACE systemAuditCallbackObjectAce(Set<AceFlags> aceFlags, Set<AccessMask> accessMask,
                                                   UUID objectType, UUID inheritedObjectType,
                                                   SID sid, byte[] applicationData) {
        return new AceType4(new AceHeader(SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, aceFlags), toLong(accessMask), objectType, inheritedObjectType, sid, applicationData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.15 SYSTEM_RESOURCE_ATTRIBUTE_ACE
     */
    public static ACE systemResourceAttributeAce(Set<AceFlags> aceFlags, byte[] attributeData) {
        return new AceType3(new AceHeader(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, aceFlags), 0, SID.EVERYONE, attributeData);
    }

    /**
     * [MS-DTYP].pdf 2.4.4.16 SYSTEM_SCOPED_POLICY_ID_ACE
     */
    public static ACE systemScopedPolicyIdAce(Set<AceFlags> aceFlags, SID sid) {
        return new AceType1(new AceHeader(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, aceFlags), 0, sid);
    }
}
