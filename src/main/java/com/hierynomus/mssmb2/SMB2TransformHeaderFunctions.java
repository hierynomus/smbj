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
package com.hierynomus.mssmb2;

import com.hierynomus.smb.SMBBuffer;

/***
 * [MS-SMB2].pdf 2.2.41 SMB2 TRANSFORM_HEADER helper functions
 */
public class SMB2TransformHeaderFunctions {
    // 2.2.41 SMB2 TRANSFORM_HEADER -- ProtocolId (4 bytes)
    public static final byte[] SMB2_TRANSFORM_HEADER_PROTOCOL_ID = new byte[]{(byte) 0xFD, 'S', 'M', 'B'};
    // 2.2.41 SMB2 TRANSFORM_HEADER
    public static final int SMB2_TRANSFORM_HEADER_SIZE = 52;
    // RFC 5116  section 5.1 and 5.3, https://tools.ietf.org/html/rfc5116#section-5.1
    public static final int AUTHENTICATION_TAG_LENGTH = 16; // authentication tag with a length of 16 octets (128bits) is used
    // 2.2.41 SMB2 TRANSFORM_HEADER -- Nonce (16 bytes)
    public static final int AES128CCM_NONCE_LENGTH = 11;
    public static final int AES128GCM_NONCE_LENGTH = 12;
    // 2.2.41 SMB2 TRANSFORM_HEADER - SessionId (8 bytes)
    public static final int SMB2_TRANSFORM_HEADER_SESSION_ID_OFFSET = 44;

    public static byte[] newAAD(byte[] nonce, int plainTextSize, long sessionId) {
        SMBBuffer aadTemp = new SMBBuffer();

        aadTemp.putRawBytes(nonce); // Nonce (16 bytes)
        aadTemp.putUInt32(plainTextSize); // OriginalMessageSize (4 bytes)
        aadTemp.putReserved2(); // Reserved (2 bytes)
        aadTemp.putUInt16(1); // Flags/EncryptionAlgorithm (2 bytes)
        aadTemp.putLong(sessionId); // SessionId (8 bytes)

        return aadTemp.getCompactData();
    }

    public static byte[] getActualNonce(Smb2EncryptionCipher algorithm, byte[] nonceField) {
        byte[] nonce;
        switch (algorithm) {
            case AES_128_CCM: {
                nonce = new byte[AES128CCM_NONCE_LENGTH];
                System.arraycopy(nonceField, 0, nonce, 0, AES128CCM_NONCE_LENGTH);
                break;
            }
            case AES_128_GCM: {
                nonce = new byte[AES128GCM_NONCE_LENGTH];
                System.arraycopy(nonceField, 0, nonce, 0, AES128GCM_NONCE_LENGTH);
                break;
            }
            default:
                throw new IllegalStateException("Unknown encryption algorithm (not supported) when getting nonce.");
        }
        return nonce;
    }
}
