//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if os(Linux) || os(Android)

/// Represents the `epoll` filters/events we might use:
///
///  - `hangup` corresponds to `EPOLLHUP`
///  - `readHangup` corresponds to `EPOLLRDHUP`
///  - `input` corresponds to `EPOLLIN`
///  - `output` corresponds to `EPOLLOUT`
///  - `error` corresponds to `EPOLLERR`
private struct EpollFilterSet: OptionSet, Equatable {
    typealias RawValue = UInt8

    let rawValue: RawValue

    static let _none = EpollFilterSet([])
    static let hangup = EpollFilterSet(rawValue: 1 << 0)
    static let readHangup = EpollFilterSet(rawValue: 1 << 1)
    static let input = EpollFilterSet(rawValue: 1 << 2)
    static let output = EpollFilterSet(rawValue: 1 << 3)
    static let error = EpollFilterSet(rawValue: 1 << 4)

    init(rawValue: RawValue) {
        self.rawValue = rawValue
    }
}

extension EpollFilterSet {
    /// Convert NIO's `SelectorEventSet` set to a `EpollFilterSet`
    init(selectorEventSet: SelectorEventSet) {
        var thing: EpollFilterSet = [.error, .hangup]
        if selectorEventSet.contains(.read) {
            thing.formUnion(.input)
        }
        if selectorEventSet.contains(.write) {
            thing.formUnion(.output)
        }
        if selectorEventSet.contains(.readEOF) {
            thing.formUnion(.readHangup)
        }
        self = thing
    }
}

extension SelectorEventSet {
    var epollEventSet: UInt32 {
        assert(self != ._none)
        // EPOLLERR | EPOLLHUP is always set unconditionally anyway but it's easier to understand if we explicitly ask.
        var filter: UInt32 = Epoll.EPOLLERR | Epoll.EPOLLHUP
        let epollFilters = EpollFilterSet(selectorEventSet: self)
        if epollFilters.contains(.input) {
            filter |= Epoll.EPOLLIN
        }
        if epollFilters.contains(.output) {
            filter |= Epoll.EPOLLOUT
        }
        if epollFilters.contains(.readHangup) {
            filter |= Epoll.EPOLLRDHUP
        }
        assert(filter & Epoll.EPOLLHUP != 0) // both of these are reported
        assert(filter & Epoll.EPOLLERR != 0) // always and can't be masked.
        return filter
    }

    fileprivate init(epollEvent: Epoll.epoll_event) {
        var selectorEventSet: SelectorEventSet = ._none
        if epollEvent.events & Epoll.EPOLLIN != 0 {
            selectorEventSet.formUnion(.read)
        }
        if epollEvent.events & Epoll.EPOLLOUT != 0 {
            selectorEventSet.formUnion(.write)
        }
        if epollEvent.events & Epoll.EPOLLRDHUP != 0 {
            selectorEventSet.formUnion(.readEOF)
        }
        if epollEvent.events & Epoll.EPOLLHUP != 0 || epollEvent.events & Epoll.EPOLLERR != 0 {
            selectorEventSet.formUnion(.reset)
        }
        self = selectorEventSet
    }
}

extension Selector: _SelectorBackendProtocol {
    func initialiseState0() throws {
        self.selectorFD = try Epoll.epoll_create(size: 128)
        self.eventFD = try EventFd.eventfd(initval: 0, flags: Int32(EventFd.EFD_CLOEXEC | EventFd.EFD_NONBLOCK))
        self.timerFD = try TimerFd.timerfd_create(clockId: CLOCK_MONOTONIC, flags: Int32(TimerFd.TFD_CLOEXEC | TimerFd.TFD_NONBLOCK))

        self.lifecycleState = .open

        var ev = Epoll.epoll_event()
        ev.events = SelectorEventSet.read.epollEventSet
        ev.data.fd = self.eventFD

        try Epoll.epoll_ctl(epfd: self.selectorFD, op: Epoll.EPOLL_CTL_ADD, fd: self.eventFD, event: &ev)

        var timerev = Epoll.epoll_event()
        timerev.events = Epoll.EPOLLIN | Epoll.EPOLLERR | Epoll.EPOLLRDHUP
        timerev.data.fd = self.timerFD
        try Epoll.epoll_ctl(epfd: self.selectorFD, op: Epoll.EPOLL_CTL_ADD, fd: self.timerFD, event: &timerev)
    }

    func deinitAssertions0() {
        assert(self.eventFD == -1, "self.eventFD == \(self.eventFD) in deinitAssertions0, forgot close?")
        assert(self.timerFD == -1, "self.timerFD == \(self.timerFD) in deinitAssertions0, forgot close?")
    }

    func register0<S: Selectable>(selectable: S, fd: Int, interested: SelectorEventSet) throws {
        var ev = Epoll.epoll_event()
        ev.events = interested.epollEventSet
        ev.data.fd = Int32(fd)

        try Epoll.epoll_ctl(epfd: self.selectorFD, op: Epoll.EPOLL_CTL_ADD, fd: ev.data.fd, event: &ev)
    }

    func reregister0<S: Selectable>(selectable: S, fd: Int, oldInterested: SelectorEventSet, newInterested: SelectorEventSet) throws {
        var ev = Epoll.epoll_event()
        ev.events = newInterested.epollEventSet
        ev.data.fd = Int32(fd)

        _ = try Epoll.epoll_ctl(epfd: self.selectorFD, op: Epoll.EPOLL_CTL_MOD, fd: ev.data.fd, event: &ev)
    }

    func deregister0<S: Selectable>(selectable: S, fd: Int, oldInterested: SelectorEventSet) throws {
        var ev = Epoll.epoll_event()
        _ = try Epoll.epoll_ctl(epfd: self.selectorFD, op: Epoll.EPOLL_CTL_DEL, fd: Int32(fd), event: &ev)
    }
    
    /// Apply the given `SelectorStrategy` and execute `body` once it's complete (which may produce `SelectorEvent`s to handle).
    ///
    /// - parameters:
    ///     - strategy: The `SelectorStrategy` to apply
    ///     - body: The function to execute for each `SelectorEvent` that was produced.
    func whenReady0(strategy: SelectorStrategy, _ body: (SelectorEvent<R>) throws -> Void) throws -> Void {
        assert(self.myThread == NIOThread.current)
        guard self.lifecycleState == .open else {
            throw IOError(errnoCode: EBADF, reason: "can't call whenReady for selector as it's \(self.lifecycleState).")
        }
        let ready: Int

        switch strategy {
        case .now:
            ready = Int(try Epoll.epoll_wait(epfd: self.selectorFD, events: events, maxevents: Int32(eventsCapacity), timeout: 0))
        case .blockUntilTimeout(let timeAmount):
            // Only call timerfd_settime if we're not already scheduled one that will cover it.
            // This guards against calling timerfd_settime if not needed as this is generally speaking
            // expensive.
            let next = NIODeadline.now() + timeAmount
            if next < self.earliestTimer {
                self.earliestTimer = next

                var ts = itimerspec()
                ts.it_value = timespec(timeAmount: timeAmount)
                try TimerFd.timerfd_settime(fd: self.timerFD, flags: 0, newValue: &ts, oldValue: nil)
            }
            fallthrough
        case .block:
            ready = Int(try Epoll.epoll_wait(epfd: self.selectorFD, events: events, maxevents: Int32(eventsCapacity), timeout: -1))
        }

        // start with no deregistrations happened
        self.deregistrationsHappened = false
        // temporary workaround to stop us delivering outdated events; possibly set in `deregister`
        for i in 0..<ready where !self.deregistrationsHappened {
            let ev = events[i]
            switch ev.data.fd {
            case self.eventFD:
                var val = EventFd.eventfd_t()
                // Consume event
                _ = try EventFd.eventfd_read(fd: self.eventFD, value: &val)
            case self.timerFD:
                // Consume event
                var val: UInt64 = 0
                // We are not interested in the result
                _ = try! Posix.read(descriptor: self.timerFD, pointer: &val, size: MemoryLayout.size(ofValue: val))

                // Processed the earliest set timer so reset it.
                self.earliestTimer = .distantFuture
            default:
                // If the registration is not in the Map anymore we deregistered it during the processing of whenReady(...). In this case just skip it.
                if let registration = registrations[Int(ev.data.fd)] {
                    var selectorEvent = SelectorEventSet(epollEvent: ev)
                    // we can only verify the events for i == 0 as for i > 0 the user might have changed the registrations since then.
                    assert(i != 0 || selectorEvent.isSubset(of: registration.interested), "selectorEvent: \(selectorEvent), registration: \(registration)")

                    // in any case we only want what the user is currently registered for & what we got
                    selectorEvent = selectorEvent.intersection(registration.interested)

                    guard selectorEvent != ._none else {
                        continue
                    }

                    try body((SelectorEvent(io: selectorEvent, registration: registration)))
                }
            }
        }
        growEventArrayIfNeeded(ready: ready)
    }

    /// Close the `Selector`.
    ///
    /// After closing the `Selector` it's no longer possible to use it.
     public func close0() throws {
        self.externalSelectorFDLock.withLock {
            // We try! all of the closes because close can only fail in the following ways:
            // - EINTR, which we eat in Posix.close
            // - EIO, which can only happen for on-disk files
            // - EBADF, which can't happen here because we would crash as EBADF is marked unacceptable
            // Therefore, we assert here that close will always succeed and if not, that's a NIO bug we need to know
            // about.
            
            try! Posix.close(descriptor: self.timerFD)
            self.timerFD = -1
            
            try! Posix.close(descriptor: self.eventFD)
            self.eventFD = -1
            
            try! Posix.close(descriptor: self.selectorFD)
            self.selectorFD = -1
        }
    }

    /* attention, this may (will!) be called from outside the event loop, ie. can't access mutable shared state (such as `self.open`) */
    func wakeup0() throws {
        assert(NIOThread.current != self.myThread)
        try self.externalSelectorFDLock.withLock {
                guard self.eventFD >= 0 else {
                    throw EventLoopError.shutdown
                }
                _ = try EventFd.eventfd_write(fd: self.eventFD, value: 1)
        }
    }
}

#endif
