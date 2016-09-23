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
package com.hierynomus.smbj.smb2

import com.hierynomus.smbj.common.SMBBuffer
import com.hierynomus.smbj.common.SmbPath
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectRequest
import com.hierynomus.smbj.smb2.messages.SMB2TreeConnectResponse
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.xml.bind.DatatypeConverter
import java.security.Security
import java.security.spec.AlgorithmParameterSpec

class SMB2TreeConnectSignatureTest extends Specification {

    def "should compute signature correctly"() {
        given:
        Security.addProvider(new BouncyCastleProvider());
//        String hexString1 = "fe534d4240000100000000000300811f0800000000000000080000000000000000000000000000007d0000c04574000092d47c8ecdb52e0e1cb806641468b6980900000048003a005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c0049006e007300740061006c006c00";
          String hexString1 = "00000082fe534d4240000100000000000300811f0800000000000000080000000000000000000000000000007d0000c045740000000000000000000000000000000000000900000048003a005c005c00720077006e00660069006c006500300031002e00720077006e002e006c006f00630061006c005c0049006e007300740061006c006c00";
        String sessionKeyHexString = "0e8c08e8b30653d7670c726d916e584e"
        String expectedSignatureHexString = "92d47c8ecdb52e0e1cb806641468b698";
        byte[] dataToSign = DatatypeConverter.parseHexBinary(hexString1);
        byte[] sessionKey = DatatypeConverter.parseHexBinary(sessionKeyHexString);
        byte[] expectedSignature = DatatypeConverter.parseHexBinary(expectedSignatureHexString);

        when:
        Mac sha256_HMAC = Mac.getInstance("HMACSHA256")
        SecretKeySpec secret_key = new SecretKeySpec(sessionKey, "HMACSHA256");
        sha256_HMAC.init(secret_key);
        byte[] signature = sha256_HMAC.doFinal(dataToSign);

        then:
        signature == expectedSignature

    }
}
