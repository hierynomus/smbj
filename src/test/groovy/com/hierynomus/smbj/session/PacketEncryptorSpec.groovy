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
package com.hierynomus.smbj.session

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.SMB2CreateDisposition
import com.hierynomus.mssmb2.SMB2CreateOptions
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2MessageFlag
import com.hierynomus.mssmb2.SMB2ShareAccess
import com.hierynomus.mssmb2.SMB2TransformHeaderFunctions
import com.hierynomus.mssmb2.Smb2EncryptionCipher
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.Charsets
import com.hierynomus.protocol.commons.EnumWithValue
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.common.Check
import com.hierynomus.smbj.common.SmbPath
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class PacketEncryptorSpec extends Specification {

  // groovy version of java's new byte[]{(byte) 0xFE, 'S', 'M', 'B'}
  byte[] smb2HeaderProtocolId = [(byte) 0xFE, (byte) 0x53, (byte) 0x4D, (byte) 0x42] as byte[]
  // groovy version of java's new byte[]{(byte) 0xFD, 'S', 'M', 'B'}
  byte[] transformHeaderProtocolId = [(byte) 0xFD, (byte) 0x53, (byte) 0x4D, (byte) 0x42] as byte[]

  def sessionKey = ByteArrayUtils.parseHex("09921d4431b171b977370bf8910900f9")
  def smb30xExpectedSigningKey = ByteArrayUtils.parseHex("8f5a6907bce9ec89b8f89e560d4e2e18")
  def smb30xExpectedEncryptionKey = ByteArrayUtils.parseHex("858e8cba1f7068969e825b2b538830c4")
  def smb30xExpectedDecryptionKey = ByteArrayUtils.parseHex("df91d31ef09a01fd4d2a093c42deef46")
  def javaBCProvider = new BouncyCastleProvider()
  def smbjBCProvider = new BCSecurityProvider()

  def "should able to encrypt a message correctly for AES-CCM"() {
    given:
    SMB2Dialect dialect = SMB2Dialect.SMB_3_0
    Smb2EncryptionCipher algorithm = Smb2EncryptionCipher.AES_128_CCM
    String path = "test.txt"
    SMB2CreateRequest message = new SMB2CreateRequest(
      dialect,
      1, 1,
      null,
      EnumSet.of(AccessMask.GENERIC_ALL),
      EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL),
      SMB2ShareAccess.ALL,
      SMB2CreateDisposition.FILE_OPEN,
      null,
      new SmbPath("127.0.0.1", "share01", path)
    )
    PacketEncryptor packetEncryptor = new PacketEncryptor(
      dialect,
      new BCSecurityProvider(),
      algorithm
    )
    packetEncryptor.init(sessionKey)

    when:
    def encryptedMessage = packetEncryptor.encrypt(message)

    then:
    encryptedMessage instanceof PacketEncryptor.EncryptedPacketWrapper

    when:
    SMBBuffer buffer = new SMBBuffer()
    encryptedMessage.write(buffer)
    // read the SMB2_TRANSFORM_HEADER
    buffer.rpos(0)
    byte[] protocolId = buffer.readRawBytes(4)
    byte[] signature = buffer.readRawBytes(16) // Signature (16 bytes)
    byte[] nonceField = buffer.readRawBytes(16) // Nonce (16 bytes)
    long originalMessageSize = buffer.readUInt32() // OriginalMessageSize (4 bytes)
    buffer.skip(2) // Reserved (2 bytes)
    int flagsOrEncryptionAlgorithm = buffer.readUInt16() // Flags/EncryptionAlgorithm (2 bytes)
    long sessionId = buffer.readLong() // SessionId (8 bytes)
    byte[] cipherText = buffer.readRawBytes((int) originalMessageSize) // encrypted packet (variable)

    then:
    // Check we see a valid header start
    Check.ensureEquals(protocolId, transformHeaderProtocolId, "Could not find SMB2_TRANSFORM_HEADER")
    // read the remaining part of the SMB2_TRANSFORM_HEADER
    flagsOrEncryptionAlgorithm == 1
    sessionId == 1

    when:
    byte[] aad = SMB2TransformHeaderFunctions.newAAD(nonceField, (int) originalMessageSize, sessionId)
    byte[] nonce = SMB2TransformHeaderFunctions.getActualNonce(algorithm, nonceField)
    GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce)
    Cipher cipher = Cipher.getInstance(algorithm.getAlgorithmName(), javaBCProvider)
    // Always use the encryptionKey to decrypt it, this is because the message is supposed to be received by Server
    // And the Server's encrypt and decrypt Keys are in reverse order of client Keys
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(smb30xExpectedEncryptionKey, algorithm.getAlgorithmName()), parameterSpec)
    cipher.updateAAD(aad)
    cipher.update(cipherText)
    byte[] plainText = cipher.doFinal(signature)
    SMBBuffer decryptedBuffer = new SMBBuffer()
    decryptedBuffer.putRawBytes(plainText)
    decryptedBuffer.rpos(0)
    // Read the plainText message
    byte[] smb2ProtocolId =  decryptedBuffer.readRawBytes(4) // ProtocolId (4 bytes)
    int headerStructureSize = decryptedBuffer.readUInt16() // StructureSize (2 bytes)
    int creditCharge = decryptedBuffer.readUInt16() // CreditCharge (2 bytes)
    long statusCode = decryptedBuffer.readUInt32() // Status (4 bytes)
    int command = decryptedBuffer.readUInt16() // Command (2 bytes)
    int creditRequest = decryptedBuffer.readUInt16() // CreditRequest/CreditResponse (2 bytes)
    long flags = decryptedBuffer.readUInt32() // Flags (4 bytes)
    long nextCommandOffset = decryptedBuffer.readUInt32() // NextCommand (4 bytes)
    long messageId = decryptedBuffer.readLong() // MessageId (4 bytes)
    decryptedBuffer.skip(4) // Reserved (4 bytes)
    long treeId = decryptedBuffer.readUInt32() // TreeId (4 bytes)
    long plainTextSessionId = decryptedBuffer.readLong() // SessionId (8 bytes)
    byte[] readSignature = decryptedBuffer.readRawBytes(16) // Signature (16 bytes)

    then:
    // Check we see a correct and valid header start
    Check.ensureEquals(smb2ProtocolId, smb2HeaderProtocolId, "Could not find SMB2 Packet header")
    headerStructureSize == 64 // StructureSize (2 bytes)
    command == 0x0005 // Command (2 bytes)
    (flags & SMB2MessageFlag.SMB2_FLAGS_SIGNED.value) == 0
    treeId == 1 // TreeId (4 bytes)
    plainTextSessionId == 1 // SessionId (8 bytes)
    Arrays.equals(readSignature, new byte[16])

    when:
    int messageStructureSize = decryptedBuffer.readUInt16() // StructureSize (2 bytes)
    byte securityFlags = decryptedBuffer.readByte() // SecurityFlags (1 byte) - Reserved
    byte oplockLevel = decryptedBuffer.readByte() // RequestedOpLockLevel (1 byte)
    long impersonationLevel = decryptedBuffer.readUInt32() // ImpersonationLevel (4 bytes) - Identification
    long smbCreateFlags = decryptedBuffer.readLong() // SmbCreateFlags (8 bytes)
    decryptedBuffer.skip(8) // Reserved (8 bytes)
    Set<AccessMask> desiredAccess = EnumWithValue.EnumUtils.toEnumSet(decryptedBuffer.readUInt32(), AccessMask.class) // DesiredAccess (4 bytes)
    Set<FileAttributes> fileAttributes = EnumWithValue.EnumUtils.toEnumSet(decryptedBuffer.readUInt32(), FileAttributes.class) // FileAttributes (4 bytes)
    Set<SMB2ShareAccess> shareAccess = EnumWithValue.EnumUtils.toEnumSet(decryptedBuffer.readUInt32(), SMB2ShareAccess.class) // ShareAccess (4 bytes)
    SMB2CreateDisposition createDisposition = EnumWithValue.EnumUtils.valueOf(decryptedBuffer.readUInt32(), SMB2CreateDisposition.class, null) // CreateDisposition (4 bytes)
    Set<SMB2CreateOptions> createOptions = EnumWithValue.EnumUtils.toEnumSet(decryptedBuffer.readUInt32(), SMB2CreateOptions.class) // CreateOptions (4 bytes)
    int nameOffset = decryptedBuffer.readUInt16() // NameOffset (2 bytes)
    int nameLength = decryptedBuffer.readUInt16() // NameLength (2 bytes)
    long createContextsOffset = decryptedBuffer.readUInt32() // CreateContextsOffset (4 bytes)
    long createContextsLength = decryptedBuffer.readUInt32() // CreateContextsLength (4 bytes)
    int createRequestBufferStartPos = decryptedBuffer.rpos()
    decryptedBuffer.rpos(nameOffset)
    byte[] nameBytes = decryptedBuffer.readRawBytes(nameLength)
    String name = new String(nameBytes, Charsets.UTF_16LE)

    then:
    messageStructureSize == 57
    securityFlags == (byte) 0
    oplockLevel == (byte) 0
    impersonationLevel == 1
    smbCreateFlags == 0
    desiredAccess == EnumSet.of(AccessMask.GENERIC_ALL)
    fileAttributes == EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
    shareAccess == SMB2ShareAccess.ALL
    createDisposition == SMB2CreateDisposition.FILE_OPEN
    createOptions.isEmpty()
    nameOffset == (headerStructureSize + messageStructureSize - 1)
    nameLength == (path.length() * 2) // time 2 because unicode
    createContextsOffset == 0L
    createContextsLength == 0L
    createRequestBufferStartPos == nameOffset
    name == path
  }
}
