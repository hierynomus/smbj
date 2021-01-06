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
package com.hierynomus.smbj.connection

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2TransformHeader
import com.hierynomus.mssmb2.SMB3EncryptionCipher
import com.hierynomus.security.bc.BCSecurityProvider
import spock.lang.Specification
import spock.lang.Unroll

class PacketEncryptorSpec extends Specification {

  def "should have correct Smb2TransformHeaderProtocolId"() {
    given:
    // groovy version of java's new byte[]{(byte) 0xFD, 'S', 'M', 'B'}
    byte[] transformHeaderProtocolId = [(byte) 0xFD, (byte) 0x53, (byte) 0x4D, (byte) 0x42] as byte[]

    when:
    byte[] receivedProtocolId = SMB2TransformHeader.ENCRYPTED_PROTOCOL_ID

    then:
    transformHeaderProtocolId == receivedProtocolId
  }

  def "should able to form the aad correctly"() {
    given:
    byte[] expectedAAD = [
      // Nonce (16 bytes)
      (byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
      // OriginalMessageSize (4 bytes)
      (byte) 0x10, (byte) 0x0, (byte) 0x0, (byte) 0x0,
      // Reserved (2 bytes)
      (byte) 0x0, (byte) 0x0,
      // Flags/EncryptionAlgorithm (2 bytes)
      (byte) 0x01, (byte) 0x0,
      // SessionId (8 bytes)
      (byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0
    ] as byte[]
    SMB2TransformHeader header = new SMB2TransformHeader([(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[], 16, 1)

    when:
    byte[] aad = new PacketEncryptor(new BCSecurityProvider()).createAAD(header)

    then:
    aad == expectedAAD
  }

  @Unroll
  def "should able to get nonce for #algorithm correctly"() {
    given:
    PacketEncryptor pe = new PacketEncryptor(new BCSecurityProvider())
    pe.cipher = algorithm

    when:
    byte[] nonce = pe.getNewNonce()

    then:
    // 2.2.41 SMB2 TRANSFORM_HEADER -- Nonce (16 bytes)
    // public static final int AES128CCM_NONCE_LENGTH = 11;
    nonce.length == nonceLength

    where:
    algorithm | nonceLength
    SMB3EncryptionCipher.AES_128_CCM | 11
    SMB3EncryptionCipher.AES_128_GCM | 12
  }
}
