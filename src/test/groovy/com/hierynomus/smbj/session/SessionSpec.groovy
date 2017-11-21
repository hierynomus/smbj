package com.hierynomus.smbj.session

import com.hierynomus.mssmb2.SMB2Dialect
import com.hierynomus.smbj.SmbConfig
import com.hierynomus.smbj.connection.Connection
import com.hierynomus.smbj.connection.NegotiatedProtocol
import com.hierynomus.smbj.event.SMBEventBus
import spock.lang.Specification

class SessionSpec extends Specification {

  def "share name cannot contain '\\'"() {
    given:
    def config = SmbConfig.createDefaultConfig()
    def connection = Stub(Connection, constructorArgs: [config, null, Mock(SMBEventBus)]) {
      getNegotiatedProtocol() >> new NegotiatedProtocol(SMB2Dialect.SMB_2_0_2, 100, 100, 100, true)
    }
    def session = new Session(connection, null, null, false, null)

    when:
    session.connectShare("foo\\bar")

    then:
    def ex = thrown(IllegalArgumentException)
    ex.message.contains("foo\\bar")
  }
}
