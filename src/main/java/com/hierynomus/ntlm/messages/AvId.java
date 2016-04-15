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
package com.hierynomus.ntlm.messages;

import com.hierynomus.protocol.commons.EnumWithValue;

public enum AvId implements EnumWithValue<AvId> {
    MsvAvEOL(0x0),
    MsvAvNbComputerName(0x01),
    MsvAvNdDomainName(0x02),
    MsvAvDnsComputerName(0x03),
    MsvAvDnsDomainName(0x04),
    MsvAvDnsTreeName(0x05),
    MsvAvFlags(0x06),
    MsvAvTimestamp(0x07),
    MsvAvSingleHost(0x08),
    MsvAvTargetName(0x09),
    MsvChannelBindings(0x0a);

    private final long value;

    AvId(long i) {
        this.value = i;
    }

    @Override
    public long getValue() {
        return value;
    }
}
