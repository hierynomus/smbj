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
package com.hierynomus.protocol.commons;

import java.util.Collection;
import java.util.EnumSet;

public interface EnumWithValue<E extends Enum<E>> {

    long getValue();

    class EnumUtils {
        public static <E extends Enum<E>> long toLong(Collection<E> set) {
            long l = 0;
            for (E e : set) {
                if (e instanceof EnumWithValue) {
                    l |= ((EnumWithValue) e).getValue();
                } else {
                    throw new IllegalArgumentException("Can only be used with EnumWithValue enums.");
                }
            }
            return l;
        }

        public static <E extends Enum<E>> EnumSet<E> toEnumSet(long l, Class<E> clazz) {
            if (!EnumWithValue.class.isAssignableFrom(clazz)) {
                throw new IllegalArgumentException("Can only be used with EnumWithValue enums.");
            }
            EnumSet<E> es = EnumSet.noneOf(clazz);
            for (E anEnum : clazz.getEnumConstants()) {
                if (isSet(l, ((EnumWithValue<?>) anEnum))) {
                    es.add(anEnum);
                }
            }
            return es;
        }

        public static <E extends EnumWithValue<?>> boolean isSet(long bytes, E value) {
            return (bytes & value.getValue()) > 0;
        }

        public static <E extends EnumWithValue<?>> E valueOf(long l, Class<E> enumClass, E defaultValue) {
            E[] enumConstants = enumClass.getEnumConstants();
            for (E enumConstant : enumConstants) {
                if (enumConstant.getValue() == l) {
                    return enumConstant;
                }
            }

            return defaultValue;
        }

        public static <E extends Enum<E>> EnumSet<E> ensureNotNull(EnumSet<E> set, Class<E> clazz) {
            if (set == null) {
                return EnumSet.noneOf(clazz);
            } else {
                return set;
            }
        }
    }
}
