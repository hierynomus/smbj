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
package com.hierynomus.smbj.common;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.hierynomus.mssmb2.SMB2Header;

public class MessageSigning {

    /**
     * check that the signature field of the SMB message buffer is correct.
     * 
     * @param buffer
     *            byte array containing the SMB message.
     * @param len
     *            message length. Note that the buffer array might contain more
     *            bytes than the message length. The len parameter indicates how
     *            many bytes of the buffer array are in the message.
     * @param signingKey
     *            the session's signing key.
     * @return
     */
    public static boolean validateSignature(byte[] buffer, int len, byte[] signingKey) {
        try {
            byte[] signature = computeSignature(buffer, len, signingKey);

            // are signatures identical?
            for (int i = 0; i < SMB2Header.SIGNATURE_SIZE; i++) {
                if (signature[i] != buffer[SMB2Header.SIGNATURE_OFFSET + i])
                    return false;
            }
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return false; // cannot check signature?
        }
    }

    /**
     * sign a SMB message buffer
     * 
     * @param buffer
     *            byte array containing the SMB message.
     * @param len
     *            message length. Note that the buffer array might contain more
     *            bytes than the message length. The len parameter indicates how
     *            many bytes of the buffer array are in the message.
     * @param signingKey
     *            the session's signing key.
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public static void signBuffer(byte[] buffer, int len, byte[] signingKey) throws InvalidKeyException,
                    NoSuchAlgorithmException {
        byte[] signature = computeSignature(buffer, len, signingKey);
        System.arraycopy(signature, 0, buffer, SMB2Header.SIGNATURE_OFFSET, 16);
    }

    /**
     * compute the HMAC signature on a SMB buffer. The calculation is performed
     * <i>as if the signature field is filled with zeros</i>.
     * 
     * @param buffer
     *            byte array containing the SMB message.
     * @param len
     *            message length. Note that the buffer array might contain more
     *            bytes than the message length. The len parameter indicates how
     *            many bytes of the buffer array are in the message.
     * @param signingKey
     *            the session's signing key.
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    private static byte[] computeSignature(byte[] buffer, int len, byte[] signingKey) throws NoSuchAlgorithmException,
                    InvalidKeyException {
        if (len < SMB2Header.STRUCTURE_SIZE)
            throw new IllegalArgumentException("Buffer must be longer than 64 bytes");
        SecretKeySpec signingKeySpec = new SecretKeySpec(signingKey, MessageSigning.HMAC_SHA256_ALGORITHM);
        Mac mac = Mac.getInstance(MessageSigning.HMAC_SHA256_ALGORITHM);
        mac.init(signingKeySpec);
        mac.update(buffer, 0, SMB2Header.SIGNATURE_OFFSET);
        for (int i = 0; i < SMB2Header.SIGNATURE_SIZE; i++)
            mac.update((byte) 0);
        mac.update(buffer, SMB2Header.STRUCTURE_SIZE, len - SMB2Header.STRUCTURE_SIZE);
        byte[] signature = mac.doFinal();
        return signature;
    }

    public static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

}
