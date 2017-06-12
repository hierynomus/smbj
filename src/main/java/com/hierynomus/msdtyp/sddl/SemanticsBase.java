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
//=========================================================================
//
//  Part of PEG parser generator Mouse.
//
//  Copyright (C) 2009 by Roman R. Redziejowski (www.romanredz.se).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
//-------------------------------------------------------------------------
//
//  Change log
//    090701 License changed by the author to Apache v.2.
//    090717 Interface 'Parser' renamed to 'CurrentRule'.
//    090810 Name changed from 'Semantics'.
//
//=========================================================================

package com.hierynomus.msdtyp.sddl;


//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
//
//  SemanticsBase
//
//HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH

@SuppressWarnings("PMD")
class SemanticsBase {
    //=====================================================================
    //
    //  Fields set by the Parser.
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  Reference to current rule in the Parser.
    //  Set when Parser instantiates Semantics.
    //-------------------------------------------------------------------
    public CurrentRule rule;

    //-------------------------------------------------------------------
    //  String that you can use to trigger trace.
    //  Set by applying method 'setTrace' to the Parser.
    //-------------------------------------------------------------------
    public String trace = "";


    //=====================================================================
    //
    //  Initialization.
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  Invoked at the beginning of each invocation of the Parser.
    //  You can override it to perform your own initialization.
    //-------------------------------------------------------------------
    public void init() {
    }


    //=====================================================================
    //
    //  Methods to be invoked from semantic actions.
    //  They call back the parser to obtain details of the environment
    //  in which the action was invoked.
    //
    //=====================================================================
    //-------------------------------------------------------------------
    //  Returns the left-hand side Phrase object.
    //-------------------------------------------------------------------
    protected Phrase lhs() {
        return rule.lhs();
    }

    //-------------------------------------------------------------------
    //  Returns the number of Phrase objects on the right-hand side.
    //-------------------------------------------------------------------
    protected int rhsSize() {
        return rule.rhsSize();
    }

    //-------------------------------------------------------------------
    //  Returns the i-th right-hand side object, 0<=i<rhs<=rhsSize().
    //  (The right-hand side objects are numbered starting with 0.)
    //-------------------------------------------------------------------
    protected Phrase rhs(int i) {
        return rule.rhs(i);
    }

    //-------------------------------------------------------------------
    //  Returns as one String the text represented
    //  by the right-hand side objects numbered i through j-1,
    //  where 0<=i<j<=rhsSize().
    //  (The right-hand side objects are numbered starting with 0.)
    //-------------------------------------------------------------------
    protected String rhsText(int i, int j) {
        return rule.rhsText(i, j);
    }

}
