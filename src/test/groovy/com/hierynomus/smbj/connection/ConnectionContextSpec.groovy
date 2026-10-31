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

import com.hierynomus.msdtyp.FileTime
import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.messages.SMB2NegotiateResponse
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.connection.SMBProtocolNegotiator.NegotiationContext
import com.hierynomus.smbj.server.Server
import spock.lang.Specification
import spock.lang.Unroll

class ConnectionContextSpec extends Specification {

    @Unroll
    def "leasing support requires client and server capabilities"() {
        given:
        def builder = SmbConfig.builder()
        if (!leasingEnabled) {
            builder.withDirectoryLeasingEnabled(false)
        }
        def config = builder.build()
        def context = new ConnectionContext(config.getClientGuid(), "127.0.0.1", 445, config)
        def capabilities = EnumSet.noneOf(SMB2GlobalCapability)
        if (serverFileLeasing) {
            capabilities.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_LEASING)
        }
        if (serverDirectoryLeasing) {
            capabilities.add(SMB2GlobalCapability.SMB2_GLOBAL_CAP_DIRECTORY_LEASING)
        }
        def server = new Server("127.0.0.1", 445)
        server.init(UUID.randomUUID(), dialect, 0, capabilities)
        def response = new SMB2NegotiateResponse()
        response.dialect = dialect
        response.systemTime = FileTime.now()
        def negotiation = Stub(NegotiationContext) {
            getNegotiationResponse() >> response
            getServer() >> server
        }

        when:
        context.negotiated(negotiation)

        then:
        context.supportsFileLeasing() == expectedFileLeasing
        context.supportsDirectoryLeasing() == expectedDirectoryLeasing

        where:
        leasingEnabled | serverFileLeasing | serverDirectoryLeasing | dialect                | expectedFileLeasing | expectedDirectoryLeasing
        false          | true              | true                   | SMB2Dialect.SMB_3_0    | false               | false
        true           | true              | true                   | SMB2Dialect.SMB_3_0    | true                | true
        true           | true              | true                   | SMB2Dialect.SMB_3_0_2  | true                | true
        true           | true              | true                   | SMB2Dialect.SMB_3_1_1  | true                | true
        true           | false             | false                  | SMB2Dialect.SMB_3_0    | false               | false
        true           | true              | false                  | SMB2Dialect.SMB_3_0    | true                | false
        true           | false             | true                   | SMB2Dialect.SMB_3_0    | false               | true
        true           | true              | true                   | SMB2Dialect.SMB_2_1    | true                | false
    }
}
