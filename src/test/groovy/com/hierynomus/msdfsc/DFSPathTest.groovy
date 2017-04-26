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

import com.hierynomus.smbj.common.SmbPath
import spock.lang.Specification
import spock.lang.Unroll

class DFSPathTest extends Specification {

  @Unroll
  def "should parse #smbPath"() {
    given:
    def path = new DFSPath(smbPath)

    expect:
    path.pathComponents == components

    where:
    smbPath        | components
    "\\a\\b\\c\\d" | ["a", "b", "c", "d"]
    "\\a"          | ["a"]
    "\\a\\b"       | ["a", "b"]
  }

  def "should replace path prefix"() {
    given:
    def path = new DFSPath("\\a\\b\\d")

    when:
    def replacedPath = path.replacePrefix("\\a\\b", "\\z\\x\\y")

    then:
    replacedPath.pathComponents == ["z", "x", "y", "d"]
  }

//  def "test parsePath typical path"() {
//    def out;
//    when:
//    out = DFS.parsePath("\\a\\b\\c\\d");
//
//    then:
//    out.length == 4;
//    out[0] == "a";
//    out[1] == "b";
//    out[2] == "c";
//    out[3] == "d";
//  }
//
//  def "test parsePath starts with double slash"() {
//    def out;
//    when:
//    out = DFS.parsePath("\\\\a\\b\\c\\d");
//
//    then:
//    out.length == 4;
//    out[0] == "a";
//    out[1] == "b";
//    out[2] == "c";
//    out[3] == "d";
//  }
//
//  def "test parsePath starts with no slash"() {
//    def out;
//    when:
//    out = DFS.parsePath("a\\b\\c\\d");
//
//    then:
//    out.length == 4;
//    out[0] == "a";
//    out[1] == "b";
//    out[2] == "c";
//    out[3] == "d";
//  }
//
//  def "test parsePath single element"() {
//    def out;
//    when:
//    out = DFS.parsePath("a");
//
//    then:
//    out.length == 1;
//    out[0] == "a";
//  }
//
//  def "test normalizePath typical path"() {
//    def out;
//    when:
//    out = DFS.normalizePath("\\a\\b\\c\\d");
//
//    then:
//    out == "\\a\\b\\c\\d";
//  }
//
//  def "test normalizePath starts with double slash"() {
//    def out;
//    when:
//    out = DFS.normalizePath("\\\\a\\b\\c\\d");
//
//    then:
//    out == "\\a\\b\\c\\d";
//  }
//
//  def "test normalizePath single element"() {
//    def out;
//    when:
//    out = DFS.normalizePath("\\a");
//
//    then:
//    out == "\\a";
//  }
}
