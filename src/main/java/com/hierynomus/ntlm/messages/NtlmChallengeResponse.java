/*
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

import com.hierynomus.protocol.commons.buffer.Buffer;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.EnumSet;

import static com.hierynomus.ntlm.messages.NtlmNegotiateFlag.EnumUtils;

/**
 * [MS-NLMP].pdf 2.2.1.1 NEGOTIATE_MESSAGE
 */
public class NtlmChallengeResponse extends NtlmPacket {

    long flags = NtlmNegotiate.DEFAULT_FLAGS;

    byte[] lmResponse;
    byte[] ntResponse;
    byte[] sessionKey;
    String userName;
    String domainName;
    String workStation;

    public NtlmChallengeResponse(byte[] lmResponse, byte[] ntResponse, byte[] sessionKey, String userName, String domainName, String workStation) {
        super();
        this.lmResponse = lmResponse;
        this.ntResponse = ntResponse;
        this.sessionKey = sessionKey;
        this.userName = userName;
        this.domainName = domainName;
        this.workStation = workStation;
    }

    public void write(Buffer.PlainBuffer buffer) {
        buffer.putString("NTLMSSP\0", Charset.forName("UTF-8")); // Signature (8 bytes)
        buffer.putUInt32(0x03); // MessageType (4 bytes)

        int offset = 64; // for the offset
        try {
            writeFields(buffer, offset , new byte[][]
                    {
                            (lmResponse == null) ? new byte[0] : lmResponse,
                            (ntResponse == null) ? new byte[0] : ntResponse,
                            (domainName == null) ? new byte[0] : domainName.getBytes(UNI_ENCODING),
                            (userName == null) ? new byte[0] : userName.getBytes(UNI_ENCODING), // TODO ALways using unicode, check?
                            (workStation == null) ? new byte[0] : workStation.getBytes(UNI_ENCODING),
                            (sessionKey == null) ? new byte[0] : sessionKey,

                    }, new Object[]{flags});
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new RuntimeException("Unexpected exception while writing", ioe);
        }
    }
}
