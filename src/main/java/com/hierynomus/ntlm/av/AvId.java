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
package com.hierynomus.ntlm.av;

import com.hierynomus.protocol.commons.EnumWithValue;

public enum AvId implements EnumWithValue<AvId> {
    MsvAvEOL(0x00L),
    MsvAvNbComputerName(0x01L),
    MsvAvNbDomainName(0x02L),
    MsvAvDnsComputerName(0x03L),
    MsvAvDnsDomainName(0x04L),
    MsvAvDnsTreeName(0x05L),
    MsvAvFlags(0x06L),
    MsvAvTimestamp(0x07L),
    MsvAvSingleHost(0x08L),
    MsvAvTargetName(0x09L),
    MsvAvChannelBindings(0x0AL);

    private final long value;

    AvId(long i) {
        this.value = i;
    }

    @Override
    public long getValue() {
        return value;
    }
}
