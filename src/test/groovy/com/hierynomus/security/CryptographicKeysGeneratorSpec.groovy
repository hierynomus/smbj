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
package com.hierynomus.security

import com.hierynomus.protocol.commons.ByteArrayUtils
import spock.lang.Specification

import javax.crypto.spec.SecretKeySpec

class CryptographicKeysGeneratorSpec extends Specification {

  def sessionKey = ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9")
  def smb30xExpectedSigningKey = ByteArrayUtils.parseHex("8f5a6907bce9ec89b8f89e560d4e2e18")
  def smb30xExpectedEncryptionKey = ByteArrayUtils.parseHex("858e8cba1f7068969e825b2b538830c4")
  def smb30xExpectedDecryptionKey = ByteArrayUtils.parseHex("df91d31ef09a01fd4d2a093c42deef46")

  def "should able to generate correct signingKey for Smb30x"() {
    when:
    def generatedKey = CryptographicKeysGenerator.generateKey(
      new SecretKeySpec(sessionKey, ""),
      CryptographicKeysGenerator.Smb30xSigningLabelByteArray,
      CryptographicKeysGenerator.Smb30xSigningContextByteArray,
      "AesCmac"
    )

    then:
    Arrays.equals(smb30xExpectedSigningKey, generatedKey.getEncoded())
  }

  def "should able to generate correct encryptionKey for Smb30x"() {
    when:
    def generatedKey = CryptographicKeysGenerator.generateKey(
      new SecretKeySpec(sessionKey, ""),
      CryptographicKeysGenerator.Smb30xEncryptLabelByteArray,
      CryptographicKeysGenerator.Smb30xEncryptContextByteArray,
      "AES/CCM/NoPadding"
    )

    then:
    Arrays.equals(smb30xExpectedEncryptionKey, generatedKey.getEncoded())
  }

  def "should able to generate correct decryptionKey for Smb30x"() {
    when:
    def generatedKey = CryptographicKeysGenerator.generateKey(
      new SecretKeySpec(sessionKey, ""),
      CryptographicKeysGenerator.Smb30xDecryptLabelByteArray,
      CryptographicKeysGenerator.Smb30xDecryptContextByteArray,
      "AES/CCM/NoPadding"
    )

    then:
    Arrays.equals(smb30xExpectedDecryptionKey, generatedKey.getEncoded())
  }
}
