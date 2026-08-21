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
package com.hierynomus.smbj.share

import com.hierynomus.msfscc.fileinformation.FileDirectoryInformation
import com.hierynomus.msfscc.fileinformation.FileDirectoryQueryableInformation
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation
import spock.lang.Specification

class LeasedDirectoryCacheSpec extends Specification {

    def "populate then serve returns the listing"() {
        given:
        def cache = new LeasedDirectoryCache()
        def l = [Mock(FileDirectoryQueryableInformation), Mock(FileDirectoryQueryableInformation)]

        when:
        cache.populate("dir", FileIdBothDirectoryInformation, null, l)

        then:
        cache.serve("dir", FileIdBothDirectoryInformation, null) == l
        cache.size() == 1
        cache.getPopulates() == 1
        cache.getServeHits() == 1
    }

    def "a miss returns null"() {
        expect:
        new LeasedDirectoryCache().serve("dir", FileIdBothDirectoryInformation, null) == null
    }

    def "a different informationClass is a different key"() {
        given:
        def cache = new LeasedDirectoryCache()
        def l = [Mock(FileDirectoryQueryableInformation)]
        cache.populate("dir", FileIdBothDirectoryInformation, null, l)

        expect:
        cache.serve("dir", FileDirectoryInformation, null) == null
        cache.serve("dir", FileIdBothDirectoryInformation, null) == l
    }

    def "a real searchPattern is never cached (bypass)"() {
        given:
        def cache = new LeasedDirectoryCache()

        expect:
        !LeasedDirectoryCache.isCacheable("*.txt")
        LeasedDirectoryCache.isCacheable(null)
        LeasedDirectoryCache.isCacheable("")

        when:
        cache.populate("dir", FileIdBothDirectoryInformation, "*.txt", [Mock(FileDirectoryQueryableInformation)])

        then:
        cache.serve("dir", FileIdBothDirectoryInformation, "*.txt") == null
        cache.size() == 0
    }

    def "invalidateAll evicts everything (the break hook)"() {
        given:
        def cache = new LeasedDirectoryCache()
        cache.populate("dir", FileIdBothDirectoryInformation, null, [Mock(FileDirectoryQueryableInformation)])

        when:
        cache.invalidateAll()

        then:
        cache.serve("dir", FileIdBothDirectoryInformation, null) == null
        cache.size() == 0
    }

    def "served list is an unmodifiable snapshot"() {
        given:
        def cache = new LeasedDirectoryCache()
        cache.populate("dir", FileIdBothDirectoryInformation, null, [Mock(FileDirectoryQueryableInformation)])

        when:
        cache.serve("dir", FileIdBothDirectoryInformation, null).add(null)

        then:
        thrown(UnsupportedOperationException)
    }
}
