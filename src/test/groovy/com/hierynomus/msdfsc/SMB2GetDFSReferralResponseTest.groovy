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
package com.hierynomus.msdfsc

import com.hierynomus.msdfsc.messages.DFSReferral
import com.hierynomus.msdfsc.messages.SMB2GetDFSReferralResponse
import com.hierynomus.smb.SMBBuffer
import spock.lang.Specification
import spock.lang.Unroll

class SMB2GetDFSReferralResponseTest extends Specification {

  @Unroll
  def "encode dfs referral response #serverType"() {
    given:
    def buf = new SMBBuffer(data.decodeHex())
    def dfsRefResp = new SMB2GetDFSReferralResponse("\\SERVERHOST\\Sales")

    when:
    dfsRefResp.read(buf)

    then:
    dfsRefResp.referralEntries.size() == 1
    dfsRefResp.referralHeaderFlags.asList() == [SMB2GetDFSReferralResponse.ReferralHeaderFlags.ReferralServers, SMB2GetDFSReferralResponse.ReferralHeaderFlags.StorageServers]
    def refEntry = dfsRefResp.referralEntries[0]
    refEntry.versionNumber == 4
    refEntry.serverType == serverType
    refEntry.referralEntryFlags == 4
    refEntry.dfsPath == "\\10.0.0.10\\sales"
    refEntry.dfsAlternatePath == "\\10.0.0.10\\sales"
    refEntry.path == "\\SERVERHOST\\Sales"
    refEntry.ttl == 300

    where:
    data << ["260001000300000004002200010004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000",
             "260001000300000004002200000004002c010000220044006600000000000000000000000000000000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C00310030002E0030002E0030002E00310030005C00730061006C006500730000005C0053004500520056004500520048004F00530054005C00530061006C00650073000000"]
    serverType << [DFSReferral.ServerType.ROOT, DFSReferral.ServerType.LINK]
  }

  def "encode dfs referral response domain"() {
    given:
    def data = "260001000300000003002200010002002c0100002200010030000000000000000000000000000000000044004f004d00410049004e00000053004500520056004500520048004f00530054000000"
    def buf = new SMBBuffer(data.decodeHex())
    def dfsRefResp = new SMB2GetDFSReferralResponse("\\SERVERHOST\\Sales")

    when:
    dfsRefResp.read(buf)

    then:
    def referralEntry = dfsRefResp.referralEntries[0]
    referralEntry.versionNumber == 3
    referralEntry.serverType == DFSReferral.ServerType.ROOT
    referralEntry.referralEntryFlags == 0x2
    referralEntry.dfsPath == "\\SERVERHOST\\Sales"
    referralEntry.dfsAlternatePath == null
    referralEntry.path == null
    referralEntry.ttl == 300
    referralEntry.specialName == "DOMAIN"
    referralEntry.expandedNames == ["SERVERHOST"] as ArrayList
  }

}
