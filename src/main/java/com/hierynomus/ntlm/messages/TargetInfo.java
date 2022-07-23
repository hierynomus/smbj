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

import java.util.HashMap;
import java.util.Map;

import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.protocol.commons.Charsets;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TargetInfo {
    private static final Logger logger = LoggerFactory.getLogger(TargetInfo.class);

    private Map<AvId, Object> targetInfo = new HashMap<>();

    TargetInfo() {}

    TargetInfo readFrom(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        while (true) {
            int l = buffer.readUInt16();
            AvId avId = EnumWithValue.EnumUtils.valueOf(l, AvId.class, null); // AvId (2 bytes)
            logger.trace("NTLM channel contains {}({}) TargetInfo", avId, l);
            int avLen = buffer.readUInt16(); // AvLen (2 bytes)
            switch (avId) {
                case MsvAvEOL:
                    // End of sequence
                    return this;
                case MsvAvNbComputerName:
                case MsvAvNdDomainName:
                case MsvAvDnsComputerName:
                case MsvAvDnsDomainName:
                case MsvAvDnsTreeName:
                case MsvAvTargetName:
                    targetInfo.put(avId, buffer.readString(Charsets.UTF_16LE, avLen / 2));
                    break;
                case MsvAvFlags:
                    targetInfo.put(avId, buffer.readUInt32(Endian.LE));
                    break;
                case MsvAvTimestamp:
                    targetInfo.put(avId, MsDataTypes.readFileTime(buffer));
                    break;
                case MsvAvSingleHost:
                    break;
                case MsvChannelBindings:
                    break;
                default:
                    throw new IllegalStateException("Encountered unhandled AvId: " + avId);
            }
        }
    }

    public void writeTo(Buffer.PlainBuffer buffer) {
        for (AvId key : targetInfo.keySet()) {
            buffer.putUInt16((int) key.getValue()); // AvId (2 bytes)
            switch (key) {
                case MsvAvNbComputerName:
                case MsvAvNdDomainName:
                case MsvAvDnsComputerName:
                case MsvAvDnsDomainName:
                case MsvAvDnsTreeName:
                case MsvAvTargetName:
                    String val = getAvPairString(key);
                    buffer.putUInt16(val.length() * 2); // AvLen (2 bytes)
                    buffer.putString(val, Charsets.UTF_16LE);
                    break;
                case MsvAvFlags:
                    buffer.putUInt16(4); // AvLen (2 bytes)
                    buffer.putUInt32((long) getAvPairObject(key), Endian.LE);
                    break;
                case MsvAvTimestamp:
                    buffer.putUInt16(8); // AvLen (2 bytes)
                    FileTime ft = (FileTime) getAvPairObject(key);
                    MsDataTypes.putFileTime(ft, buffer);
                    break;
                case MsvAvSingleHost:
                case MsvChannelBindings:
                    break;
                default:
                    throw new IllegalStateException("Encountered unhandled AvId: " + key);
            }
        }
        buffer.putUInt16((int) AvId.MsvAvEOL.getValue()); // AvId (2 bytes)
        buffer.putUInt16(0); // AvLen (2 bytes)
    }

    public TargetInfo copy() {
        TargetInfo c = new TargetInfo();
        c.targetInfo = new HashMap<>(targetInfo);
        return c;
    }

    public Object getAvPairObject(AvId key) {
        return this.targetInfo.get(key);
    }

    public void putAvPairString(AvId key, String value) {
        this.targetInfo.put(key, value);
    }

    public String getAvPairString(AvId key) {
        Object obj = this.targetInfo.get(key);
        if (obj == null)
            return null;
        else
            return String.valueOf(obj);
    }

}
