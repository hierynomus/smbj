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

import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Buffer.BufferException;
import com.hierynomus.protocol.commons.EnumWithValue;

public class AvPairFactory {

    public static AvPair<?> read(Buffer<?> buffer) throws BufferException {
        int l = buffer.readUInt16();
        AvId avId = EnumWithValue.EnumUtils.valueOf(l, AvId.class, null); // AvId (2 bytes)
        switch (avId) {
            case MsvAvEOL:
                return new AvPairEnd().read(buffer);
            case MsvAvNbComputerName:
            case MsvAvNbDomainName:
            case MsvAvDnsComputerName:
            case MsvAvDnsDomainName:
            case MsvAvDnsTreeName:
            case MsvAvTargetName:
                return new AvPairString(avId).read(buffer);
            case MsvAvFlags:
                return new AvPairFlags().read(buffer);
            case MsvAvTimestamp:
                return new AvPairTimestamp().read(buffer);
            case MsvAvSingleHost:
                return new AvPairSingleHost().read(buffer);
            case MsvAvChannelBindings:
                return new AvPairChannelBindings().read(buffer);
            default:
                throw new IllegalStateException("Encountered unhandled AvId: " + avId);

        }
    }
}
