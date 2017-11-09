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

import spock.lang.Specification

class ReferralCacheNodeTest extends Specification {

  def "should build up trie with entry at leaf"() {
    given:
    def root = new ReferralCache.ReferralCacheNode("<root>")
    def entry = Mock(ReferralCache.ReferralCacheEntry)

    when:
    root.addReferralEntry(["path", "to", "entry"].iterator(), entry)

    then:
    root.childNodes.containsKey("path")
    root.childNodes.size() == 1
    with(root.childNodes.get("path")) {
      pathComponent == "path"
      childNodes.containsKey("to")
      childNodes.size() == 1
    }
    root.getReferralEntry(["path", "to", "entry"].iterator()) == entry
  }

  def "should return null for non-matching prefix"() {
    given:
    def root = new ReferralCache.ReferralCacheNode("<root>")
    def entry = Mock(ReferralCache.ReferralCacheEntry)

    when:
    root.addReferralEntry(["path", "to", "entry"].iterator(), entry)

    then:
    root.getReferralEntry(["path", "wrong", "left", "turn"].iterator()) == null
  }

  def "should return deepest match"() {
    given:
    def root = new ReferralCache.ReferralCacheNode("<root>")
    def entry = Mock(ReferralCache.ReferralCacheEntry)
    def entry2 = Mock(ReferralCache.ReferralCacheEntry)

    when:
    root.addReferralEntry(["left", "right"].iterator(), entry)
    root.addReferralEntry(["left", "right", "left"].iterator(), entry2)

    then:
    root.getReferralEntry(["left", "right"].iterator()) == entry
    root.getReferralEntry(["left", "right", "left"].iterator()) == entry2
  }

  def "should ignore path case"() {
    given:
    def root = new ReferralCache.ReferralCacheNode("<root>")
    def entry = Mock(ReferralCache.ReferralCacheEntry)

    when:
    root.addReferralEntry(["left", "right"].iterator(), entry)

    then:
    root.getReferralEntry(["LEFt", "rIgHt"].iterator()) == entry
  }
}
