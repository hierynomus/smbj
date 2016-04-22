package com.hierynomus.msdtyp.ace;

import com.hierynomus.protocol.commons.EnumWithValue;

public enum AceObjectFlags implements EnumWithValue<AceObjectFlags> {

    NONE(0x00000000L),
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
