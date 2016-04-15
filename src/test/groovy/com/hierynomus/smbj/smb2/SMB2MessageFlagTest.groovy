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

import com.hierynomus.protocol.commons.EnumWithValue
import spock.lang.Specification

class SMB2MessageFlagTest extends Specification {

    def "should correctly detect that flag is set"() {
        given:
        long b = 0x10000001

        when:
        def flagses = EnumWithValue.EnumUtils.toEnumSet(b, SMB2MessageFlag.class)

        then:
        flagses.size() == 2
        flagses.contains(SMB2MessageFlag.SMB2_FLAGS_DFS_OPERATIONS)
        flagses.contains(SMB2MessageFlag.SMB2_FLAGS_SERVER_TO_REDIR)
    }
}
