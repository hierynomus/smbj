package com.hierynomus.msdtyp.ace;

import com.hierynomus.protocol.commons.EnumWithValue;

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
