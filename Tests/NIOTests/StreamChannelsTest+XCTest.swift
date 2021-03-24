//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//
// StreamChannelsTest+XCTest.swift
//
import XCTest

///
/// NOTE: This file was generated by generate_linux_tests.rb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

extension StreamChannelTest {

   @available(*, deprecated, message: "not actually deprecated. Just deprecated to allow deprecated tests (which test deprecated functionality) without warnings")
   static var allTests : [(String, (StreamChannelTest) -> () throws -> Void)] {
      return [
                ("testEchoBasic", testEchoBasic),
                ("testSyncChannelOptions", testSyncChannelOptions),
                ("testChannelReturnsNilForDefaultSyncOptionsImplementation", testChannelReturnsNilForDefaultSyncOptionsImplementation),
// FIXME:                ("testWritabilityStartsTrueGoesFalseAndBackToTrue", testWritabilityStartsTrueGoesFalseAndBackToTrue),
// FIXME:                ("testHalfCloseOwnOutput", testHalfCloseOwnOutput),
                ("testHalfCloseOwnInput", testHalfCloseOwnInput),
                ("testDoubleShutdownInput", testDoubleShutdownInput),
                ("testDoubleShutdownOutput", testDoubleShutdownOutput),
                ("testWriteFailsAfterOutputClosed", testWriteFailsAfterOutputClosed),
                ("testVectorWrites", testVectorWrites),
// FIXME:                ("testLotsOfWritesWhilstOtherSideNotReading", testLotsOfWritesWhilstOtherSideNotReading),
                ("testFlushInWritePromise", testFlushInWritePromise),
                ("testWriteAndFlushInChannelWritabilityChangedToTrue", testWriteAndFlushInChannelWritabilityChangedToTrue),
                ("testWritabilityChangedDoesNotGetCalledOnSimpleWrite", testWritabilityChangedDoesNotGetCalledOnSimpleWrite),
                ("testWriteAndFlushFromReentrantFlushNowTriggeredOutOfWritabilityWhereOuterSaysAllWrittenAndInnerDoesNot", testWriteAndFlushFromReentrantFlushNowTriggeredOutOfWritabilityWhereOuterSaysAllWrittenAndInnerDoesNot),
                ("testCloseInReEntrantFlushNowCall", testCloseInReEntrantFlushNowCall),
           ]
   }
}

