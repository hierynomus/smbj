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
package com.hierynomus.smbj.common

import spock.lang.Specification
import spock.lang.Unroll

class SmbPathSpec extends Specification {

  @Unroll
  def "should correctly parse '#stringPath' as path"() {
    given:
    def smbPath = SmbPath.parse(stringPath)

    expect:
    smbPath.hostname == host
    smbPath.shareName == share
    smbPath.path == path

    where:
    stringPath                                 | host        | share | path
    "localhost\\C\$\\My Documents\\Jeroen"     | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\localhost\\C\$\\My Documents\\Jeroen"   | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\\\localhost\\C\$\\My Documents\\Jeroen" | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\\\localhost\\C\$"                       | "localhost" | "C\$" | null
  }

  @Unroll
  def "should implement equals/hashCode"() {
    given:
    def parsedPath = SmbPath.parse(stringPath)
    def constructedPath = new SmbPath(host, share, path)

    expect:
    parsedPath == constructedPath
    parsedPath.hashCode() == constructedPath.hashCode()

    where:
    stringPath                                 | host        | share | path
    "localhost\\C\$\\My Documents\\Jeroen"     | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\localhost\\C\$\\My Documents\\Jeroen"   | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\\\localhost\\C\$\\My Documents\\Jeroen" | "localhost" | "C\$" | "My Documents\\Jeroen"
    "\\\\localhost\\C\$"                       | "localhost" | "C\$" | null
  }

  @Unroll
  def "should output corrent UNC path for #host/#share/#path"() {
    expect:
    new SmbPath(host, share, path).toUncPath() == uncPath

    where:
    host        | share   | path                   | uncPath
    "localhost" | "C\$"   | "My Documents\\Jeroen" | "\\\\localhost\\C\$\\My Documents\\Jeroen"
    "localhost" | "C\$"   | null                   | "\\\\localhost\\C\$"
    "localhost" | "\\C\$" | null                   | "\\\\localhost\\C\$"
  }

  @Unroll
  def "should #yesno be on same host for #path1 and #path2"() {
    given:
    def smbPath1 = SmbPath.parse(path1)
    def smbPath2 = SmbPath.parse(path2)

    expect:
    smbPath1.isOnSameHost(smbPath2) == sameHost

    where:
    path1 | path2 | sameHost
    "localhost\\foo" | "localhost\\foo" | true
    "localhost\\foo" | "localhost\\bar" | true
    "localhost\\foo" | "bieblobla\\foo" | false
    yesno = sameHost ? "" : "not"
  }

  @Unroll
  def "should #yesno be on same share for #path1 and #path2"() {
    given:
    def smbPath1 = SmbPath.parse(path1)
    def smbPath2 = SmbPath.parse(path2)

    expect:
    smbPath1.isOnSameShare(smbPath2) == sameHost

    where:
    path1 | path2 | sameHost
    "localhost\\foo" | "localhost\\foo" | true
    "localhost\\foo" | "localhost\\bar" | false
    "localhost\\foo" | "bieblobla\\foo" | false
    yesno = sameHost ? "" : "not"
  }
}
