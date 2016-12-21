package com.netease.rawsock

import java.net.{Inet4Address, InetAddress}

import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.namednumber.UdpPort
import org.pcap4j.packet.{EthernetPacket, IpV4Packet, UdpPacket, UnknownPacket}
import org.pcap4j.util.MacAddress


object app extends App {
  val snapLen = 65536;
  val mode = PromiscuousMode.PROMISCUOUS
  val timeout = 10;
  val nif = Pcaps.getDevByName("dummy1")
  val loNif = Pcaps.getDevByName("lo")
  // In real app, should use filter to catch only packets.
  // For loopback, should set a fiter that never receive any packets or simple ignore it.
  val handle = nif.openLive(snapLen, mode, timeout)
  val loHandle = loNif.openLive(snapLen, mode, timeout)

  println(s"handle blocking mode is ${handle.getBlockingMode().toString}")
  while (true) {
    val packet = handle.getNextPacketEx()
    println(packet.toString)

    val etherPacket = EthernetPacket.newPacket(packet.getRawData, 0, packet.getRawData.size)
    val ipv4Packet = IpV4Packet.newPacket(etherPacket.getPayload.getRawData, 0, etherPacket.getPayload.getRawData.size)
    val udpPacket = UdpPacket.newPacket(ipv4Packet.getPayload.getRawData, 0, ipv4Packet.getPayload.getRawData.size)

    val udpBuilder = new UdpPacket.Builder()
      .srcPort(UdpPort.getInstance(12345.toShort))
      .dstPort(UdpPort.getInstance(4789.toShort))
      // Plus 8 is udp header length
      .length((udpPacket.getPayload.getRawData.size + 8).toShort)
      .payloadBuilder(new UnknownPacket.Builder().rawData(udpPacket.getPayload.getRawData))

    val ipv4Builder = ipv4Packet.getBuilder
      .dstAddr(InetAddress.getByName("169.254.1.1").asInstanceOf[Inet4Address])
      .srcAddr(InetAddress.getByName("169.254.1.2").asInstanceOf[Inet4Address])
      .payloadBuilder(udpBuilder)

    // Mac address is nonsense for loopback packet injection.
    val replyPacket = etherPacket.getBuilder
        .dstAddr(MacAddress.getByName("00:00:00:00:00:00"))
        .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
      .payloadBuilder(ipv4Builder).build()
    // Decode the inner VXLAN packet and re-Inject it as VXLAN packet
    // through loopback interface to VTEP address 169.254.1.1.
    println("send packet to loopback")
    loHandle.sendPacket(replyPacket)
  }

  handle.close()
}

// RawSocket is not satisfied, comment out.

//import com.savarese.rocksaw.net.RawSocket
//
///**
//  * Created by hzzhangdongya on 16-12-20.
//  */
//object app extends App {
//  println("test rocksaw library")
//  val dummySock = new RawSocket()
//  val loSock = new RawSocket()
//
//  // We only want to receive VXLAN packet in UDP frame from dummy1 interface.
//  dummySock.open(RawSocket.PF_INET, RawSocket.getProtocolByName("UDP"))
//  dummySock.bindDevice("dummy1")
//
//  while (true) {
//    var data = Array[Byte]()
//    var len = dummySock.read(data)
//    if (len > 0) {
//      println(s"read len $len")
//      println(data.toString)
//    }
//
//    Thread.sleep(50)
//  }
//}
