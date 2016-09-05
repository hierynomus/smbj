package com.hierynomus.smbj

import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import org.bouncycastle.jce.provider.BouncyCastleProvider
import spock.lang.Specification

import java.security.Security

class IntegrationTest extends Specification {
  def IP = "172.16.37.142"
  def AUTH = new AuthenticationContext("Administrator", "xeb1aLabs".toCharArray(), "")

  def setupSpec() {
    if (!Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
      Security.addProvider(new BouncyCastleProvider())
    }
  }

  def "should connect"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)

    then:
    connection.connected
  }

  def "should authenticate"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    session.close()

    then:
    session.sessionId != null
  }

  def "should connect to share"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare("Go")
    session.close()

    then:
    share instanceof DiskShare
    share.treeConnect.treeId != null
    !share.isConnected()
  }

  def "should check directory existence"() {
    given:
    def client = new SMBClient()

    when:
    def connection = client.connect(IP)
    def session = connection.authenticate(AUTH)
    def share = session.connectShare("Go") as DiskShare

    then:
    share.folderExists("api")
    !share.folderExists("foo")

    cleanup:
    session.close()
  }
}
