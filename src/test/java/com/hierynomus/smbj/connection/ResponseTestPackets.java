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
package com.hierynomus.smbj.connection;

import com.hierynomus.mserref.NtStatus;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2MessageFlag;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.mssmb2.SMB2PacketHeader;
import com.hierynomus.smb.SMBBuffer;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

final class ResponseTestPackets {
    static final long SESSION_ID = 42;
    static final int MEMBER_SIZE = 72;
    static final SecretKey KEY = new SecretKeySpec(new byte[] {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    }, SMBSessionBuilder.HMAC_SHA256_ALGORITHM);

    private ResponseTestPackets() {
    }

    static SMB2Packet response(long messageId) {
        return response(messageId, SMB2MessageCommandCode.SMB2_ECHO, SESSION_ID, true,
            NtStatus.STATUS_SUCCESS, new byte[] {4, 0, 0, 0});
    }

    static SMB2Packet response(long messageId, SMB2MessageCommandCode command, long sessionId,
                              boolean signed, NtStatus status, final byte[] body) {
        SMB2Packet packet = new SMB2Packet(body.length, SMB2Dialect.SMB_2_1, command, sessionId) {
            @Override
            protected void writeTo(SMBBuffer buffer) {
                buffer.putRawBytes(body);
            }
        };
        packet.getHeader().setMessageId(messageId);
        packet.getHeader().setStatusCode(status.getValue());
        packet.getHeader().setCreditResponse(3);
        packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR);
        if (signed) {
            packet.getHeader().setFlag(SMB2MessageFlag.SMB2_FLAGS_SIGNED);
        }
        return packet;
    }

    static byte[] frame(SMB2Packet... members) throws Exception {
        SMBBuffer frame = new SMBBuffer();
        for (int i = 0; i < members.length; i++) {
            SMB2Packet packet = members[i];
            SMBBuffer body = new SMBBuffer();
            packet.write(body);
            int paddedLength = (body.wpos() + 7) & ~7;
            packet.getHeader().setNextCommandOffset(i + 1 < members.length ? paddedLength : 0);
            SMBBuffer buffer = new SMBBuffer();
            packet.write(buffer);
            buffer.putReserved(paddedLength - buffer.wpos());
            byte[] data = Arrays.copyOf(buffer.array(), buffer.wpos());
            // The production writer emits request status and credit fields.
            putUInt32(data, 8, packet.getHeader().getStatusCode());
            int credits = packet.getHeader().getCreditResponse();
            data[14] = (byte) credits;
            data[15] = (byte) (credits >>> 8);
            if (packet.getHeader().isFlagSet(SMB2MessageFlag.SMB2_FLAGS_SIGNED)) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(KEY);
                byte[] signature = mac.doFinal(data);
                System.arraycopy(signature, 0, data, SMB2PacketHeader.SIGNATURE_OFFSET, SMB2PacketHeader.SIGNATURE_SIZE);
            }
            frame.putRawBytes(data);
        }
        return Arrays.copyOf(frame.array(), frame.wpos());
    }

    static void putUInt32(byte[] data, int offset, long value) {
        for (int i = 0; i < 4; i++) {
            data[offset + i] = (byte) (value >>> (8 * i));
        }
    }
}
