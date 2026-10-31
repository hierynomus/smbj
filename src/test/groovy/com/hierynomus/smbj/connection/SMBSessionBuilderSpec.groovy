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

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.mserref.NtStatus
import com.hierynomus.mssmb2.SMB2GlobalCapability
import com.hierynomus.mssmb2.SMB2MessageCommandCode
import com.hierynomus.mssmb2.SMB2MessageConverter
import com.hierynomus.mssmb2.SMB2Packet
import com.hierynomus.mssmb2.SMB2PacketData
import com.hierynomus.mssmb2.SMB3EncryptionCipher
import com.hierynomus.mssmb2.SMB3HashAlgorithm
import com.hierynomus.mssmb2.messages.SMB2SessionSetup
import com.hierynomus.protocol.commons.ByteArrayUtils
import com.hierynomus.security.bc.BCSecurityProvider
import com.hierynomus.smb.SMBBuffer
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.auth.AuthenticateResponse
import com.hierynomus.smbj.common.SMBRuntimeException
import com.hierynomus.smbj.event.SMBEventBus
import com.hierynomus.smbj.server.Server
import com.hierynomus.smbj.session.SMB2GuestSigningRequiredException
import com.hierynomus.smbj.session.SessionContext
import com.hierynomus.smbj.testing.PacketProcessor
import com.hierynomus.smbj.testing.StubAuthenticator
import com.hierynomus.smbj.testing.StubTransportLayerFactory
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import spock.lang.Specification

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

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

  def "should able to generate SigningKey, EncryptionKey And DecryptionKey with encryption supported for Smb30x"() {
    given:
    def smb30xExpectedSigningKey = ByteArrayUtils.parseHex("8f5a6907bce9ec89b8f89e560d4e2e18")
    def smb30xExpectedEncryptionKey = ByteArrayUtils.parseHex("858e8cba1f7068969e825b2b538830c4")
    def smb30xExpectedDecryptionKey = ByteArrayUtils.parseHex("df91d31ef09a01fd4d2a093c42deef46")
    def connectionContext = Mock(ConnectionContext)
    connectionContext.supportsEncryption() >> true
    connectionContext.getCipherId() >> SMB3EncryptionCipher.AES_128_CCM
    def connection = Mock(Connection)
    connection.getConnectionContext() >> connectionContext
    def response = Mock(SMB2SessionSetup)
    response.getSessionFlags() >> Collections.emptySet()
    def context = new SessionContext()
    context.setSessionKey(new SecretKeySpec(sessionKey, HMAC_SHA256_ALGORITHM))

    when:
    def sessionBuilder = new SMBSessionBuilder(connection, config, null)
    sessionBuilder.deriveKeys(response, SMB2Dialect.SMB_3_0, context)

    then:
    context.getSigningKey() != null
    smb30xExpectedSigningKey == context.getSigningKey().encoded
    context.getEncryptionKey() != null
    smb30xExpectedEncryptionKey == context.getEncryptionKey().encoded
    context.getDecryptionKey() != null
    smb30xExpectedDecryptionKey == context.getDecryptionKey().encoded
  }

  def "should able to generate signingKey only without encryption supported for Smb30x"() {
    given:
    def smb30xExpectedSigningKey = ByteArrayUtils.parseHex("8f5a6907bce9ec89b8f89e560d4e2e18")
    def connectionContext = Mock(ConnectionContext)
    connectionContext.supportsEncryption() >> false
    connectionContext.getCipherId() >> SMB3EncryptionCipher.AES_128_CCM
    def connection = Mock(Connection)
    connection.getConnectionContext() >> connectionContext
    def response = Mock(SMB2SessionSetup)
    response.getSessionFlags() >> Collections.emptySet()
    def context = new SessionContext()
    context.setSessionKey(new SecretKeySpec(sessionKey, HMAC_SHA256_ALGORITHM))

    when:
    def sessionBuilder = new SMBSessionBuilder(connection, config, null)
    sessionBuilder.deriveKeys(response, SMB2Dialect.SMB_3_0, context)

    then:
    context.getSigningKey() != null
    smb30xExpectedSigningKey == context.getSigningKey().encoded
    context.getEncryptionKey() == null
    context.getDecryptionKey() == null
  }

    private static final List<SMB2Dialect> DIALECTS = [SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1,
        SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1]
    private final AuthenticationContext credentials = new AuthenticationContext("user", "password".toCharArray(), "domain")

    def "should verify a signed final SESSION_SETUP response for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [challenge: true])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        fixture.connection.preauthSessionTable.activeSessions().empty
        session.signingRequired
        !session.guest
        !session.anonymous
        !session.sessionContext.encryptData
        dialect != SMB2Dialect.SMB_3_1_1 || session.sessionContext.preauthIntegrityHashValue == fixture.hash

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << DIALECTS
    }

    def "should reject a changed final SESSION_SETUP signature for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [mutate: { byte[] bytes -> bytes[48] ^= 1 }])

        when:
        fixture.connection.authenticate(credentials)

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << DIALECTS
    }

    def "should reject an unsigned final SESSION_SETUP response for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [signed: false])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << DIALECTS
    }

    def "should reject tampered SESSION_SETUP flags for #dialect and #flag"() {
        given:
        // Clear ENCRYPT_DATA; set the other flags.
        def fixture = sessionSetupConnection(dialect, [flags: flag == 4 ? 4 : 0,
            mutate: { byte[] bytes -> bytes[66] ^= flag }])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag] << DIALECTS.collectMany { d -> (d.isSmb3x() ? [1, 2, 4] : [1, 2]).collect { f -> [d, f] } }
    }

    def "should reject correctly signed guest or anonymous fallback for #dialect and #flag"() {
        given:
        def fixture = sessionSetupConnection(dialect, [flags: flag,
            clientRequired: clientRequired, serverRequired: serverRequired])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.class == (flag == 1 ? SMB2GuestSigningRequiredException : SMBRuntimeException)
        flag == 1 || assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag, clientRequired, serverRequired] << DIALECTS.collectMany { d ->
            [1, 2].collectMany { f -> [[d, f, true, false], [d, f, false, true]] }
        }
    }

    def "should reject unsigned guest or anonymous fallback for #dialect and #flag"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: clientRequired, serverRequired: serverRequired,
            signed: false, flags: flag])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.class == (flag == 1 ? SMB2GuestSigningRequiredException : SMBRuntimeException)
        flag == 1 || assertSecurityFailure(failure)
        flag != 2 || failure.message =="Server answered with an anonymous (null) session that cannot be verified while signing is required"
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag, clientRequired, serverRequired] << DIALECTS.collectMany { d ->
            [1, 2].collectMany { f -> [[d, f, true, false], [d, f, false, true]] }
        }
    }

    def "should accept optional guest or anonymous fallback for #dialect and #flag when signed is #signed"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, serverRequired: false,
            signed: signed, flags: flag])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        session.guest == (flag == 1)
        session.anonymous == (flag == 2)
        !session.signingRequired

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag, signed] << DIALECTS.collectMany { d ->
            [1, 2].collectMany { f -> [true, false].collect { s -> [d, f, s] } }
        }
    }

    def "should skip final SESSION_SETUP signature verification when signing is disabled for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, signingEnabled: false,
            mutate: { byte[] bytes -> bytes[48] ^= 1 }])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        !session.signingRequired

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << [SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1]
    }

    def "should reject a required final SESSION_SETUP signature without a signing key for #dialect"() {
        given:
        def authenticatorFactory = new StubAuthenticator.Factory() {
            @Override
            StubAuthenticator create() {
                return new StubAuthenticator() {
                    @Override
                    AuthenticateResponse authenticate(AuthenticationContext auth, byte[] token, ConnectionContext context) {
                        def response = super.authenticate(auth, token, context)
                        response.setSessionKey(null)
                        return response
                    }
                }
            }
        }
        def fixture = sessionSetupConnection(dialect, [authenticatorFactory: authenticatorFactory])

        when:
        fixture.connection.authenticate(credentials)

        then:
        def failure = thrown(SMBRuntimeException)
        assertSecurityFailure(failure)
        failure.message == "SESSION_SETUP response signature verification failed: no signing key"
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << DIALECTS
    }

    def "should reject a final SESSION_SETUP response after an altered preauth challenge"() {
        given:
        def fixture = sessionSetupConnection(SMB2Dialect.SMB_3_1_1, [challenge: true, alterChallenge: true])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)
    }

    def "should request the required SESSION_SETUP SecurityMode"() {
        given:
        def fixture = sessionSetupConnection(SMB2Dialect.SMB_2_1,
            [clientRequired: clientRequired, serverRequired: serverRequired, challenge: true])

        when:
        fixture.connection.authenticate(credentials)

        then:
        fixture.requests.size() == 2
        fixture.requests.every { byte[] bytes -> bytes[67] == expectedMode }

        cleanup:
        fixture.connection.close(true)

        where:
        clientRequired | serverRequired | expectedMode
        true           | false          | 2
        false          | true           | 2
        true           | true           | 2
        false          | false          | 1
    }

    def "should accept an unsigned optional SESSION_SETUP response for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, signed: false])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        !session.signingRequired

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << [SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_3_0]
    }

    def "should accept an unsigned optional encrypted SESSION_SETUP response for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, serverRequired: false,
            signed: false, flags: 4])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        session.sessionContext.encryptData
        session.sessionContext.encryptionKey != null
        session.shouldEncryptData()
        !session.signingRequired

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << [SMB2Dialect.SMB_3_0, SMB2Dialect.SMB_3_0_2]
    }

    def "should reject a bad optional SESSION_SETUP signature for #dialect and #flag"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, flags: flag,
            mutate: { byte[] bytes -> bytes[48] ^= 1 }])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag] << DIALECTS.collectMany { d ->
            (d.isSmb3x() ? [0, 1, 2, 4] : [0, 1, 2]).collect { f -> [d, f] }
        }
    }

    def "should require a final signature for SMB311 or server signing"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: false, serverRequired: serverRequired,
            signed: false])

        when:
        fixture.connection.authenticate(credentials).connectShare("share")

        then:
        def failure = thrown(SMBRuntimeException)
        failure.message.contains("SESSION_SETUP response signature verification failed")
        assertSecurityFailure(failure)
        assertRejectedSession(fixture)

        cleanup:
        fixture.connection.close(true)

        where:
        dialect                | serverRequired
        SMB2Dialect.SMB_3_1_1   | false
        SMB2Dialect.SMB_2_1     | true
    }

    def "should apply verified encryption flags for #dialect"() {
        given:
        def fixture = sessionSetupConnection(dialect, [flags: 4])

        when:
        def session = fixture.connection.authenticate(credentials)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        session.sessionContext.encryptData
        !session.signingRequired

        cleanup:
        fixture.connection.close(true)

        where:
        dialect << DIALECTS.findAll { it.isSmb3x() }
    }

    def "should preserve application chosen anonymous or guest sessions for #dialect and #flag"() {
        given:
        def fixture = sessionSetupConnection(dialect, [clientRequired: flag == 2, signed: false, flags: flag])
        def auth = flag == 1 ? AuthenticationContext.guest() : AuthenticationContext.anonymous()

        when:
        def session = fixture.connection.authenticate(auth)

        then:
        fixture.connection.sessionTable.find(42L).is(session)
        session.guest == (flag == 1)
        session.anonymous == (flag == 2)
        !session.signingRequired
        !dialect.isSmb3x() || session.sessionContext.signingKey == null

        cleanup:
        fixture.connection.close(true)

        where:
        [dialect, flag] << DIALECTS.collectMany { d -> [1, 2].collect { f -> [d, f] } }
    }

    private static boolean assertSecurityFailure(SMBRuntimeException failure) {
        assert failure.class == SMBRuntimeException
        return true
    }

    private static boolean assertRejectedSession(Map fixture) {
        assert fixture.connection.sessionTable.activeSessions().empty
        assert fixture.connection.preauthSessionTable.activeSessions().empty
        assert fixture.commands.every { it == SMB2MessageCommandCode.SMB2_SESSION_SETUP }
        return true
    }

    private Map sessionSetupConnection(SMB2Dialect dialect, Map options = [:]) {
        def fixture = [requests: [], commands: [], hash: new byte[64]]
        PacketProcessor processor = { SMB2Packet request ->
            fixture.commands.add(request.header.message)
            assert request instanceof SMB2SessionSetup : "Unexpected request after SESSION_SETUP"
            def requestBuffer = new SMBBuffer()
            request.write(requestBuffer)
            byte[] requestBytes = requestBuffer.compactData
            fixture.requests.add(requestBytes)
            if (dialect == SMB2Dialect.SMB_3_1_1) {
                fixture.hash = preauthHash(fixture.hash as byte[], requestBytes)
            }

            byte[] responseBytes
            if (options.challenge && fixture.requests.size() == 1) {
                responseBytes = sessionSetupResponse(request, NtStatus.STATUS_MORE_PROCESSING_REQUIRED, 0, false)
                if (dialect == SMB2Dialect.SMB_3_1_1) {
                    fixture.hash = preauthHash(fixture.hash as byte[], responseBytes)
                }
                if (options.alterChallenge) {
                    responseBytes[72] ^= 1
                }
            } else {
                boolean signed = options.get('signed', true)
                responseBytes = sessionSetupResponse(request, NtStatus.STATUS_SUCCESS, options.get('flags', 0) as int, signed)
                if (signed) {
                    signSessionSetup(responseBytes, dialect, fixture.hash as byte[])
                }
                if (options.mutate) {
                    options.mutate.call(responseBytes)
                }
            }
            return new SMB2MessageConverter().readPacket(request, new SMB2PacketData(responseBytes))
        } as PacketProcessor
        def testConfig = SmbConfig.builder()
            .withDialects(dialect)
            .withSigningRequired(options.get('clientRequired', true) as boolean)
            .withSigningEnabled(options.get('signingEnabled', true) as boolean)
            .withSecurityProvider(new BCSecurityProvider())
            .withAuthenticators(options.get('authenticatorFactory', new StubAuthenticator.Factory()))
            .withTransportLayerFactory(new StubTransportLayerFactory(processor))
            .withTransactTimeout(1, TimeUnit.SECONDS)
            .build()
        def protocol = new NegotiatedProtocol(dialect, 65536, 65536, 65536, false)
        def initialHash = new byte[64]
        def testContext = Stub(ConnectionContext) {
            getNegotiatedProtocol() >> protocol
            getClientCapabilities() >> EnumSet.noneOf(SMB2GlobalCapability)
            getGssNegotiateToken() >> new byte[0]
            getPreauthIntegrityHashValue() >> initialHash
            getPreauthIntegrityHashId() >> SMB3HashAlgorithm.SHA_512
            getCipherId() >> SMB3EncryptionCipher.AES_128_CCM
            supportsEncryption() >> dialect.isSmb3x()
            isServerRequiresSigning() >> (options.get('serverRequired', false) as boolean)
            getServer() >> new Server("server", 445)
        }
        // Start after negotiation with a fixed preauth hash; all SESSION_SETUP traffic uses the stub transport.
        def connection = new Connection(testConfig, null, new SMBEventBus(), null)
        connection.@connectionContext = testContext
        connection.transport.connect(InetSocketAddress.createUnresolved("server", 445))
        fixture.connection = connection
        return fixture
    }

    private static byte[] sessionSetupResponse(SMB2Packet request, NtStatus status, int flags, boolean signed) {
        def buffer = new SMBBuffer()
        buffer.putRawBytes([(byte) 0xfe, 0x53, 0x4d, 0x42] as byte[])
        buffer.putUInt16(64) // Header StructureSize
        buffer.putUInt16(1) // CreditCharge
        buffer.putUInt32(status.value)
        buffer.putUInt16(SMB2MessageCommandCode.SMB2_SESSION_SETUP.value as int)
        buffer.putUInt16(request.header.creditRequest)
        buffer.putUInt32(signed ? 9 : 1) // SERVER_TO_REDIR, optionally SIGNED
        buffer.putUInt32(0) // NextCommand
        buffer.putLong(request.header.messageId)
        buffer.putReserved(8) // Reserved, TreeId
        buffer.putLong(42L)
        buffer.putReserved(16) // Signature
        buffer.putUInt16(9) // SESSION_SETUP response StructureSize
        buffer.putUInt16(flags)
        buffer.putUInt16(72) // SecurityBufferOffset
        buffer.putUInt16(3)
        buffer.putRawBytes([0x11, 0x22, 0x33] as byte[])
        buffer.putRawBytes([0x55, 0x66] as byte[]) // Unparsed bytes must also be covered by the signature.
        return buffer.compactData
    }

    private static byte[] preauthHash(byte[] previous, byte[] packet) {
        def digest = MessageDigest.getInstance("SHA-512")
        digest.update(previous)
        return digest.digest(packet)
    }

    private void signSessionSetup(byte[] packet, SMB2Dialect dialect, byte[] preauth) {
        byte[] signature
        if (dialect.isSmb3x()) {
            // SP800-108 counter KDF, independently assembled rather than using SMBSessionBuilder.
            def input = new ByteArrayOutputStream()
            input.write([0, 0, 0, 1] as byte[])
            input.write((dialect == SMB2Dialect.SMB_3_1_1 ? "SMBSigningKey\u0000" : "SMB2AESCMAC\u0000").getBytes("US-ASCII"))
            input.write(0)
            input.write(dialect == SMB2Dialect.SMB_3_1_1 ? preauth : "SmbSign\u0000".getBytes("US-ASCII"))
            input.write([0, 0, 0, (byte) 0x80] as byte[])
            def kdf = Mac.getInstance("HmacSHA256")
            kdf.init(new SecretKeySpec(sessionKey, "HmacSHA256"))
            byte[] signingKey = Arrays.copyOf(kdf.doFinal(input.toByteArray()), 16)
            def cmac = new CMac(new AESEngine())
            cmac.init(new KeyParameter(signingKey))
            cmac.update(packet, 0, packet.length)
            signature = new byte[16]
            cmac.doFinal(signature, 0)
        } else {
            def hmac = Mac.getInstance("HmacSHA256")
            hmac.init(new SecretKeySpec(sessionKey, "HmacSHA256"))
            signature = hmac.doFinal(packet)
        }
        System.arraycopy(signature, 0, packet, 48, 16)
    }
}
