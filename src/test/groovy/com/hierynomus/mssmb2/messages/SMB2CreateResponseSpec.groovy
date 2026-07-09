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
package com.hierynomus.mssmb2.messages

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.LeaseKey
import com.hierynomus.mssmb2.SMB2LeaseState
import com.hierynomus.mssmb2.SMB2MessageConverter
import com.hierynomus.mssmb2.SMB2OplockLevel
import com.hierynomus.mssmb2.messages.create.SMB2CreateContext
import com.hierynomus.mssmb2.messages.create.SMB2LeaseCreateContext
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification

class SMB2CreateResponseSpec extends AbstractPacketReadSpec {

  static final LeaseKey KEY = new LeaseKey(ByteArrayUtils.parseHex("000102030405060708090a0b0c0d0e0f"))
  static final LeaseKey PARENT = new LeaseKey(ByteArrayUtils.parseHex("101112131415161718191a1b1c1d1e1f"))
  // Header from the known-good response above (first 64 bytes) -> a valid SMB2 CREATE response header.
  static final byte[] HEADER = Arrays.copyOfRange(ByteArrayUtils.parseHex("fe534d4240000000000000000500010001000000000000000400000000000000000000000100000009000000004000000000000000000000000000000000000059000000010000006aa787efa59dd1016aa787efa59dd1016aa787efa59dd101954ff5efa59dd101000000000000000000000000000000001000000000000000030000001000000001000000100000000000000000000000"), 0, 64)

  /** Build a CREATE response carrying OplockLevel=LEASE and a V2 RqLs granted-lease context. */
  static byte[] leaseResponseBytes() {
    def b = new SMBBuffer()
    b.putRawBytes(HEADER)
    b.putUInt16(89)              // StructureSize
    b.putByte((byte) 0xFF)       // OplockLevel = LEASE
    b.putByte((byte) 0)          // Flags
    b.putUInt32(1)               // CreateAction
    b.putReserved(32)            // Creation/LastAccess/LastWrite/ChangeTime
    b.putReserved(8)             // AllocationSize
    b.putReserved(8)             // EndOfFile
    b.putUInt32(0x10)            // FileAttributes = DIRECTORY
    b.putReserved(4)             // Reserved2
    b.putRawBytes(ByteArrayUtils.parseHex("00112233445566778899aabbccddeeff")) // FileId
    int ccField = b.wpos()
    b.putUInt32(0)               // CreateContextsOffset (placeholder)
    b.putUInt32(0)               // CreateContextsLength (placeholder)
    int ctxStart = b.wpos()      // = 152, header at 0 so equals header-relative offset
    def leaseCtx = SMB2LeaseCreateContext.v2(KEY, SMB2LeaseState.readHandle(), PARENT).toCreateContext()
    int ccLen = SMB2CreateContext.writeAll(b, [leaseCtx])
    int end = b.wpos()
    b.wpos(ccField); b.putUInt32(ctxStart); b.putUInt32(ccLen); b.wpos(end)
    return b.getCompactData()
  }

  def "should parse SMB2 Create Response without Maximal Content"() {
    given:
    String hexString1 = "fe534d4240000000000000000500010001000000000000000400000000000000000000000100000009000000004000000000000000000000000000000000000059000000010000006aa787efa59dd1016aa787efa59dd1016aa787efa59dd101954ff5efa59dd101000000000000000000000000000000001000000000000000030000001000000001000000100000000000000000000000"
    byte[] bytes1 = ByteArrayUtils.parseHex(hexString1)

    when:
    def resp = convert(bytes1)

    then:
    resp.class == SMB2CreateResponse.class
    with (resp as SMB2CreateResponse) { r ->
      r.getCreationTime() == new FileTime(131059200184264554L)
      Arrays.equals(([0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00] as byte[]), r.fileId.persistentHandle)
    }
  }

  def "should parse SMB2 Create Response with STATUS_PENDING"() {
    given:
    def hex = "fe534d424000010003010000050002000300000000000000040000000000000001000000000000004100000800280000e73d1a019d13aca24830757ebad16519090000000000000000"
    def bytes = ByteArrayUtils.parseHex(hex)

    when:
    def resp = convert(bytes)

    then:
    resp instanceof SMB2CreateResponse
    resp.getHeader().getStatusCode() == NtStatus.STATUS_PENDING.getValue()
  }

  def "parses OplockLevel=LEASE and the granted V2 lease response context"() {
    when:
    def resp = convert(leaseResponseBytes()) as SMB2CreateResponse

    then:
    resp.getOplockLevel() == SMB2OplockLevel.SMB2_OPLOCK_LEVEL_LEASE
    def lease = resp.getLeaseResponseContext()
    lease != null
    lease.isV2()
    lease.getLeaseKey() == KEY
    lease.getLeaseState() == 0x3L
    lease.isReadHandleGranted()
    lease.getParentLeaseKey() == PARENT
  }

  def "a no-context create response reports OplockLevel=NONE and no lease context"() {
    given:
    byte[] bytes = ByteArrayUtils.parseHex("fe534d4240000000000000000500010001000000000000000400000000000000000000000100000009000000004000000000000000000000000000000000000059000000010000006aa787efa59dd1016aa787efa59dd1016aa787efa59dd101954ff5efa59dd101000000000000000000000000000000001000000000000000030000001000000001000000100000000000000000000000")

    when:
    def resp = convert(bytes) as SMB2CreateResponse

    then:
    resp.getOplockLevel() == SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE
    resp.getLeaseResponseContext() == null
  }
}
