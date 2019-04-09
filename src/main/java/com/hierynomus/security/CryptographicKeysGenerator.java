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
package com.hierynomus.security;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

// [MS-SMB2] 3.1.4.2 Generating Cryptographic Keys
public class CryptographicKeysGenerator {
    private static final Logger logger = LoggerFactory.getLogger(CryptographicKeysGenerator.class);

    // [MS-SMB2].pdf 3.3.5.5.3 Handling GSS-API Authentication
    // NIST Special Publication 800-108, 5.1 KDF in Counter Mode
    private static final int KDF_R_VALUE = 32;
    private static final int KDF_L_VALUE = 16; // 16 bytes == 128 bits
    private static final byte[] KDF_L_VALUE_BYTE_ARRAY = new byte[] {(byte)0x0, (byte)0x0, (byte)0x0, (byte)0x80}; // 128 in 4 bytes, big endian
    private static final int Smb30xFixedSuffixLength = 25;
    // SMB2AESCMAC, including the terminating null character
    public static final byte[] Smb30xSigningLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'2', (byte)'A', (byte)'E', (byte)'S', (byte)'C', (byte)'M', (byte)'A', (byte)'C', (byte)'\0'};
    // SmbSign, including the terminating null character
    public static final byte[] Smb30xSigningContextByteArray = new byte[]{(byte)'S', (byte)'m', (byte)'b', (byte)'S', (byte)'i', (byte)'g', (byte)'n', (byte)'\0'};
    // SMB2AESCCM, including the terminating null character
    public static final byte[] Smb30xEncryptLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'2', (byte)'A', (byte)'E', (byte)'S', (byte)'C', (byte)'C', (byte)'M', (byte)'\0'};
    // ServerIn , including the suffix space and the terminating null character
    public static final byte[] Smb30xEncryptContextByteArray = new byte[]{(byte)'S', (byte)'e', (byte)'r', (byte)'v', (byte)'e', (byte)'r', (byte)'I', (byte)'n', (byte)' ', (byte)'\0'};
    // SMB2AESCCM, including the terminating null character
    public static final byte[] Smb30xDecryptLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'2', (byte)'A', (byte)'E', (byte)'S', (byte)'C', (byte)'C', (byte)'M', (byte)'\0'};
    // ServerOut, including the terminating null character
    public static final byte[] Smb30xDecryptContextByteArray = new byte[]{(byte)'S', (byte)'e', (byte)'r', (byte)'v', (byte)'e', (byte)'r', (byte)'O', (byte)'u', (byte)'t', (byte)'\0'};
    // SMBSigningKey, including the terminating null character
    public static final byte[] Smb311SigningLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'S', (byte)'i', (byte)'g', (byte)'n', (byte)'i', (byte)'n', (byte)'g', (byte)'K', (byte)'e', (byte)'y', (byte)'\0'};
    // SMBC2SCipherKey, including the terminating null character
    public static final byte[] Smb311EncryptLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'C', (byte)'2', (byte)'S', (byte)'C', (byte)'i', (byte)'p', (byte)'h', (byte)'e', (byte)'r', (byte)'K', (byte)'e', (byte)'y', (byte)'\0'};
    // SMBS2CCipherKey, including the terminating null character
    public static final byte[] Smb311DecryptLabelByteArray = new byte[]{(byte)'S', (byte)'M', (byte)'B', (byte)'S', (byte)'2', (byte)'C', (byte)'C', (byte)'i', (byte)'p', (byte)'h', (byte)'e', (byte)'r', (byte)'K', (byte)'e', (byte)'y', (byte)'\0'};

    public static SecretKeySpec generateKey(Key sessionKey, byte[] label, byte[] context, String algorithm) {
        // TODO add method in security provider instead of always use the BC direct

        // check is the input parameter is valid or not.
        if (sessionKey == null || sessionKey.getEncoded() == null || label == null || context == null || algorithm == null) {
            logger.error("Unable to generate key, cause by inputting null as parameter. Return null.");
            return null;
        }

        ByteArrayOutputStream fixedSuffixTemp = new ByteArrayOutputStream(Smb30xFixedSuffixLength);
        try {
            fixedSuffixTemp.write(label);
            fixedSuffixTemp.write(0);
            fixedSuffixTemp.write(context);
            fixedSuffixTemp.write(KDF_L_VALUE_BYTE_ARRAY);
        } catch (IOException e) {
            logger.error("Unable to format suffix, error occur : ", e);
            return null;
        }

        byte[] fixedSuffix = fixedSuffixTemp.toByteArray();
        KDFCounterBytesGenerator
            kdfGenerator = new KDFCounterBytesGenerator(new HMac(new SHA256Digest()));
        kdfGenerator.init(new KDFCounterParameters(sessionKey.getEncoded(), null, fixedSuffix, KDF_R_VALUE));
        byte[] generatedKey = new byte[KDF_L_VALUE];
        kdfGenerator.generateBytes(generatedKey, 0, KDF_L_VALUE);

        // return the generatedKey with assigning the algorithm (for the key to to be used)
        return new SecretKeySpec(generatedKey, algorithm);
    }
}
