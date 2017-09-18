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

import com.hierynomus.msdtyp.MsDataTypes;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * [MS-NLMP].pdf 2.2.1.2 CHALLENGE_MESSAGE
 */
public class NtlmChallenge extends NtlmPacket {
    private static final Logger logger = LoggerFactory.getLogger(NtlmChallenge.class);

    private int targetNameLen;
    private int targetNameBufferOffset;
    private EnumSet<NtlmNegotiateFlag> negotiateFlags;
    private byte[] serverChallenge;
    private WindowsVersion version;
    private int targetInfoLen;
    private int targetInfoBufferOffset;
    private String targetName;
    private Map<AvId, Object> targetInfo = new HashMap<>();
    private byte[] rawTargetInfo; // TODO remove duplicate byte array

    @Override
    public void read(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        buffer.readString(StandardCharsets.UTF_8, 8); // Signature (8 bytes) (NTLMSSP\0)
        buffer.readUInt32(); // MessageType (4 bytes)
        readTargetNameFields(buffer); // TargetNameFields (8 bytes)
        negotiateFlags = EnumWithValue.EnumUtils.toEnumSet(buffer.readUInt32(), NtlmNegotiateFlag.class); // NegotiateFlags (4 bytes)
        serverChallenge = buffer.readRawBytes(8); // ServerChallenge (8 bytes)
        buffer.skip(8); // Reserved (8 bytes)
        readTargetInfoFields(buffer); // TargetInfoFields(8 bytes)
        readVersion(buffer);
        readTargetName(buffer);
        readTargetInfo(buffer);
    }

    private void readTargetInfo(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        if (targetInfoLen > 0) {
            buffer.rpos(targetInfoBufferOffset);
            rawTargetInfo = buffer.readRawBytes(targetInfoLen);
            // Move to where buffer begins
            buffer.rpos(targetInfoBufferOffset);
            AvId avId;
            while (true) {
                int l = buffer.readUInt16();
                avId = EnumWithValue.EnumUtils.valueOf(l, AvId.class, null); // AvId (2 bytes)
                logger.trace("NTLM channel contains {}({}) TargetInfo", avId, l);
                int avLen = buffer.readUInt16(); // AvLen (2 bytes)
                switch (avId) {
                    case MsvAvEOL:
                        // End of sequence
                        return;
                    case MsvAvNbComputerName:
                    case MsvAvNdDomainName:
                    case MsvAvDnsComputerName:
                    case MsvAvDnsDomainName:
                    case MsvAvDnsTreeName:
                    case MsvAvTargetName:
                        targetInfo.put(avId, buffer.readString(StandardCharsets.UTF_16LE, avLen / 2));
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
    }

    private void readTargetName(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        if (targetNameLen > 0) {
            // Move to where buffer begins
            buffer.rpos(targetNameBufferOffset);
            targetName = buffer.readString(StandardCharsets.UTF_16LE, targetNameLen / 2);
        }
    }

    private void readVersion(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_VERSION)) {
            this.version = new WindowsVersion().readFrom(buffer);
            logger.debug("Windows version = {}", this.version);
        } else {
            buffer.skip(8);
        }
    }

    private void readTargetNameFields(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        targetNameLen = buffer.readUInt16(); // TargetNameLen (2 bytes)
        buffer.skip(2); // TargetNameMaxLen (2 bytes)
        targetNameBufferOffset = buffer.readUInt32AsInt(); // TargetNameBufferOffset (4 bytes)
    }

    private void readTargetInfoFields(Buffer.PlainBuffer buffer) throws Buffer.BufferException {
        if (negotiateFlags.contains(NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_TARGET_INFO)) {
            targetInfoLen = buffer.readUInt16(); // TargetInfoLen (2 bytes)
            buffer.skip(2); // TargetInfoMaxLen (2 bytes)
            targetInfoBufferOffset = buffer.readUInt32AsInt(); // TargetInfoBufferOffset (2 bytes)
        } else {
            buffer.skip(8);
        }
    }

    public String getTargetName() {
        return targetName;
    }

    public byte[] getServerChallenge() {
        return serverChallenge;
    }

    public EnumSet<NtlmNegotiateFlag> getNegotiateFlags() {
        return negotiateFlags;
    }

    public byte[] getTargetInfo() {
        return rawTargetInfo;
    }

    public Object getAvPairObject(AvId key) {
        return this.targetInfo.get(key);
    }

    public WindowsVersion getVersion() {
        return version;
    }
}
