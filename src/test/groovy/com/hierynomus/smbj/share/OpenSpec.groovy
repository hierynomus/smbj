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
package com.hierynomus.smbj.share

import com.hierynomus.mssmb2.SMB2FileId
import com.hierynomus.smbj.common.SmbPath
import spock.lang.Specification

class OpenSpec extends Specification {
  def fileId = new SMB2FileId(new byte[16], new byte[16])
  def path = new SmbPath("host", "share", "dir")

  def "closeSilently should not try to close a handle whose share is already closed"() {
    given:
    def share = Mock(DiskShare) { isConnected() >> false }
    def directory = new Directory(fileId, share, path)

    when:
    directory.closeSilently()

    then:
    0 * share.closeFileId(_)
  }

  def "closeSilently should close the handle while the share is connected"() {
    given:
    def share = Mock(DiskShare) { isConnected() >> true }
    def directory = new Directory(fileId, share, path)

    when:
    directory.closeSilently()

    then:
    1 * share.closeFileId(fileId)
  }
}
