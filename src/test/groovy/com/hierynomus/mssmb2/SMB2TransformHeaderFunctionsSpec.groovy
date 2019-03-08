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
package com.hierynomus.mssmb2

import spock.lang.Specification

class SMB2TransformHeaderFunctionsSpec extends Specification {

  def "should have correct Smb2TransformHeaderProtocolId"() {
    given:
    // groovy version of java's new byte[]{(byte) 0xFD, 'S', 'M', 'B'}
    byte[] transformHeaderProtocolId = [(byte) 0xFD, (byte) 0x53, (byte) 0x4D, (byte) 0x42] as byte[]

    when:
    byte[] receviedProtocolId = SMB2TransformHeaderFunctions.SMB2_TRANSFORM_HEADER_PROTOCOL_ID

    then:
    Arrays.equals(transformHeaderProtocolId, receviedProtocolId)
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
    byte[] nonceField = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    int originalMessageSize = 16
    long sessionId = 1

    when:
    byte[] aad = SMB2TransformHeaderFunctions.newAAD(nonceField, originalMessageSize, sessionId)

    then:
    Arrays.equals(aad, expectedAAD)
  }

  def "should able to get actual nonce for AES-CCM correctly"() {
    given:
    byte[] nonceField = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    byte[] expectedActualNonce = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    Smb2EncryptionCipher algorithm = Smb2EncryptionCipher.AES_128_CCM

    when:
    byte[] nonce = SMB2TransformHeaderFunctions.getActualNonce(algorithm, nonceField)

    then:
    // 2.2.41 SMB2 TRANSFORM_HEADER -- Nonce (16 bytes)
    // public static final int AES128CCM_NONCE_LENGTH = 11;
    nonce.length == 11
    Arrays.equals(nonce, expectedActualNonce)
  }

  def "should able to get actual nonce for AES-GCM correctly"() {
    given:
    byte[] nonceField = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    byte[] expectedActualNonce = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    Smb2EncryptionCipher algorithm = Smb2EncryptionCipher.AES_128_GCM

    when:
    byte[] nonce = SMB2TransformHeaderFunctions.getActualNonce(algorithm, nonceField)

    then:
    // 2.2.41 SMB2 TRANSFORM_HEADER -- Nonce (16 bytes)
    // public static final int AES128GCM_NONCE_LENGTH = 12;
    nonce.length == 12
    Arrays.equals(nonce, expectedActualNonce)
  }
}
