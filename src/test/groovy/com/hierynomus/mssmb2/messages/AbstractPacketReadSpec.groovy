package com.hierynomus.mssmb2.messages

import com.hierynomus.mssmb2.SMB2MessageConverter
import com.hierynomus.mssmb2.SMB2PacketData
import spock.lang.Shared
import spock.lang.Specification

class AbstractPacketReadSpec extends Specification {
  @Shared
  def converter = new SMB2MessageConverter()

  def convert(byte[] bytes) {
    def packetData = new SMB2PacketData(bytes)
    return converter.readPacket(null, packetData)
  }
}
