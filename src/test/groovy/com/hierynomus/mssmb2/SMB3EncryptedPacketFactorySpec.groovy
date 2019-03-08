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

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.msdtyp.MsDataTypes
import com.hierynomus.mserref.NtStatus
import com.hierynomus.msfscc.FileAttributes
import com.hierynomus.mssmb2.SMB2CreateAction
import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.mssmb2.SMB2Header
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMB2MessageFlag
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2TransformHeaderFunctions
import com.hierynomus.mssmb2.Smb2EncryptionCipher
import com.hierynomus.mssmb2.messages.SMB2CreateRequest
import com.hierynomus.mssmb2.messages.SMB2CreateResponse
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.protocol.commons.EnumWithValue
import com.hierynomus.security.DecryptPacketInfo
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smb.SMBBuffer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SMB3EncryptedPacketFactorySpec extends Specification {

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
  def smb2PacketFactory = new SMB2PacketFactory()
  def smb2MessageConverter = new SMB2MessageConverter()

  def "should able to decrypt a message correctly for AES-CCM"() {
    given:
    int creditCharge = 1
    int creditResponse = 1
    long sessionId = 1L
    int treeId = 1
    long messageId = 4L
    int headerStructureSize = 64
    long headerFlags = SMB2MessageFlag.SMB2_FLAGS_SIGNED.value
    SMB2MessageCommandCode command = SMB2MessageCommandCode.SMB2_CREATE
    NtStatus status = NtStatus.STATUS_SUCCESS
    int createResponseStructureSize = 89
    byte oplockLevel = 0x0 // SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    SMB2CreateAction createAction = SMB2CreateAction.FILE_OPENED
    long allocationSize = 4096L
    int endOfFile = 16
    Set<FileAttributes> fileAttributes = EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL)
    FileTime fileTime = FileTime.now()
    SMB2FileId fileId = new SMB2FileId()
    // the given parameter
    SMB3EncryptedPacketFactory converter = new SMB3EncryptedPacketFactory(smb2PacketFactory, smbjBCProvider)
    Smb2EncryptionCipher algorithm = Smb2EncryptionCipher.AES_128_CCM
    byte[] nonceField = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    byte[] nonce = [(byte) 0x01, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0] as byte[]
    int authenticationTagLength = SMB2TransformHeaderFunctions.AUTHENTICATION_TAG_LENGTH


    when:
    // Form the sample createResponse to byte[] to encrypt as encrypted message to test the converter decryption
    // write the header to the plainText buffer
    SMBBuffer plainTextBuffer = new SMBBuffer()
    plainTextBuffer.putRawBytes(smb2HeaderProtocolId) // ProtocolId (4 bytes)
    plainTextBuffer.putUInt16(headerStructureSize) // StructureSize (2 bytes)
    plainTextBuffer.putUInt16(creditCharge) // CreditCharge (2 bytes)
    plainTextBuffer.putUInt32(status.value) // Status (4 bytes)
    plainTextBuffer.putUInt16(command.value) // Command (2 bytes)
    plainTextBuffer.putUInt16(creditResponse) // CreditRequest/CreditResponse (2 bytes)
    plainTextBuffer.putUInt32(headerFlags) // Flags (4 bytes)
    plainTextBuffer.putUInt32(0) // NextCommand (4 bytes)
    plainTextBuffer.putLong(messageId) // MessageId (8 bytes)
    plainTextBuffer.putReserved4() // Reserved (4 bytes)
    plainTextBuffer.putUInt32(treeId) // TreeId (4 bytes)
    plainTextBuffer.putLong(sessionId) // SessionId (8 bytes)
    plainTextBuffer.putRawBytes(new byte[16]) // Signature (16 bytes)
    // put the remaining part of the createResponse
    plainTextBuffer.putUInt16(createResponseStructureSize) // StructureSize (2 bytes)
    plainTextBuffer.putByte((byte) oplockLevel) // OplockLevel (1 byte)
    plainTextBuffer.putByte((byte) 0) // Flags (1 byte)
    plainTextBuffer.putUInt32(createAction.value) // CreateAction (4 bytes)
    MsDataTypes.putFileTime(fileTime, plainTextBuffer) // CreationTime (8 bytes)
    MsDataTypes.putFileTime(fileTime, plainTextBuffer) // LastAccessTime (8 bytes)
    MsDataTypes.putFileTime(fileTime, plainTextBuffer) // LastWriteTime (8 bytes)
    MsDataTypes.putFileTime(fileTime, plainTextBuffer) // ChangeTime (8 bytes)
    plainTextBuffer.putLong(allocationSize) // AllocationSize (8 bytes)
    plainTextBuffer.putUInt64(endOfFile) // EndOfFile (8 bytes)
    plainTextBuffer.putUInt32(EnumWithValue.EnumUtils.toLong(fileAttributes)) // FileAttributes (4 bytes)
    plainTextBuffer.putReserved4() // Reserved2 (4 bytes)
    fileId.write(plainTextBuffer) // FileId (16 bytes)
    plainTextBuffer.putUInt32(0L) // CreateContextsOffset (4 bytes)
    plainTextBuffer.putUInt32(0L) // CreateContextsLength (4 bytes)
    plainTextBuffer.rpos(0)
    int plainTextSize = plainTextBuffer.available()
    byte[] plainText = plainTextBuffer.compactData

    then:
    plainTextSize == plainText.length

    when:
    SMB2PacketData plainTextPacketData = smb2PacketFactory.read(plainText)
    SMB2CreateResponse createResponse = new SMB2CreateResponse()
    createResponse.read(plainTextPacketData)

    then:
    createResponse instanceof SMB2CreateResponse

    when:
    GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce)
    byte[] aad = SMB2TransformHeaderFunctions.newAAD(nonceField, plainTextSize, sessionId)
    Cipher cipher = Cipher.getInstance(algorithm.algorithmName, javaBCProvider)
    // Always use the decryptionKey to encrypt it, this is because the message is supposed to be received by client
    // And the Server's encrypt and decrypt Keys are in reverse order of client Keys
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(smb30xExpectedDecryptionKey, algorithm.algorithmName), parameterSpec)
    cipher.updateAAD(aad)
    byte[] cipherTextWithMac = cipher.doFinal(plainText)

    then:
    cipherTextWithMac.length == plainTextSize + authenticationTagLength

    when:
    // Actual Writing the Packet with SMB2_TRANSFORM_HEADER
    SMBBuffer cipherTextBuffer = new SMBBuffer()
    cipherTextBuffer.putRawBytes(transformHeaderProtocolId) // ProtocolId (4 bytes)
    cipherTextBuffer.putRawBytes(cipherTextWithMac, plainTextSize, authenticationTagLength) // Signature (16 bytes)
    cipherTextBuffer.putRawBytes(aad) // Nonce (16 bytes), OriginalMessageSize (4 bytes), Reserved (2 bytes), Flags/EncryptionAlgorithm (2 bytes), SessionId (8 bytes)
    cipherTextBuffer.putRawBytes(cipherTextWithMac, 0, plainTextSize) // encrypted packet (variable)
    cipherTextBuffer.rpos(0)
    SMB2PacketData encryptedPacketData = converter.read(cipherTextBuffer.compactData, new DecryptPacketInfo(new SecretKeySpec(smb30xExpectedDecryptionKey, algorithm.algorithmName), algorithm))
    SMB2Packet decryptedPacket = smb2MessageConverter.readPacket(null, encryptedPacketData)

    then:
    decryptedPacket.fromDecrypt
    decryptedPacket instanceof SMB2CreateResponse

    when:
    SMB2CreateResponse decryptedCreateResponse = (SMB2CreateResponse) decryptedPacket
    SMB2Header decryptedHeader = decryptedCreateResponse.getHeader()

    then:
    decryptedHeader.statusCode == NtStatus.STATUS_SUCCESS.value
    decryptedHeader.treeId == treeId
    decryptedHeader.sessionId == sessionId
    decryptedHeader.messageId == messageId
    decryptedHeader.flags == headerFlags
    Arrays.equals(decryptedHeader.signature, new byte[16])
//    decryptedCreateResponse.endOfFile == endOfFile
//    decryptedCreateResponse.allocationSize == allocationSize
//    decryptedCreateResponse.oplockLevel == oplockLevel
    decryptedCreateResponse.creationTime == fileTime
    decryptedCreateResponse.lastAccessTime == fileTime
    decryptedCreateResponse.lastWriteTime == fileTime
    decryptedCreateResponse.changeTime == fileTime
    decryptedCreateResponse.fileAttributes == fileAttributes
  }
}
