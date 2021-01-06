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

import com.hierynomus.mssmb2.SMB3EncryptionCipher
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smbj.SmbConfig
import spock.lang.Specification

import javax.crypto.spec.SecretKeySpec

import static com.hierynomus.smbj.connection.SMBSessionBuilder.*

class SMBSessionBuilderSpec extends Specification {
  def sessionKey = ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9")
  def config = {
    def c = SmbConfig.createDefaultConfig()
    c.securityProvider = new BCSecurityProvider()
    c
  }()

  def "should able to generate correct signingKey for Smb30x"() {
    given:
    def smb30xExpectedSigningKey = ByteArrayUtils.parseHex("8f5a6907bce9ec89b8f89e560d4e2e18")

    when:
    def generatedKey = new SMBSessionBuilder(Mock(Connection), config, null).deriveKey(
      new SecretKeySpec(sessionKey, HMAC_SHA256_ALGORITHM), KDF_SIGN_LABEL, KDF_SIGN_CONTEXT, AES_128_CMAC_ALGORITHM)

    then:
    smb30xExpectedSigningKey == generatedKey.getEncoded()
  }

  def "should able to generate correct encryptionKey for Smb30x"() {
    given:
    def smb30xExpectedEncryptionKey = ByteArrayUtils.parseHex("858e8cba1f7068969e825b2b538830c4")

    when:
    def generatedKey = new SMBSessionBuilder(Mock(Connection), config, null).deriveKey(
      new SecretKeySpec(sessionKey, HMAC_SHA256_ALGORITHM), KDF_ENCDEC_LABEL, KDF_ENC_CONTEXT, SMB3EncryptionCipher.AES_128_CCM.algorithmName)

    then:
    smb30xExpectedEncryptionKey == generatedKey.getEncoded()
  }

  def "should able to generate correct decryptionKey for Smb30x"() {
    given:
    def smb30xExpectedDecryptionKey = ByteArrayUtils.parseHex("df91d31ef09a01fd4d2a093c42deef46")

    when:
    def generatedKey =  new SMBSessionBuilder(Mock(Connection), config, null).deriveKey(
      new SecretKeySpec(sessionKey, HMAC_SHA256_ALGORITHM), KDF_ENCDEC_LABEL, KDF_DEC_CONTEXT, SMB3EncryptionCipher.AES_128_CCM.algorithmName)

    then:
    smb30xExpectedDecryptionKey == generatedKey.getEncoded()
  }
}
