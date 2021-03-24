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

// This is a companion to System.swift that provides only Linux specials: either things that exist
// only on Linux, or things that have Linux-specific extensions.

#if os(Linux) || os(Android)
import CNIOLinux

internal enum TimerFd {
    public static let TFD_CLOEXEC = CNIOLinux.TFD_CLOEXEC
    public static let TFD_NONBLOCK = CNIOLinux.TFD_NONBLOCK

    @inline(never)
    public static func timerfd_settime(fd: Int32, flags: Int32, newValue: UnsafePointer<itimerspec>, oldValue: UnsafeMutablePointer<itimerspec>?) throws  {
        _ = try syscall(blocking: false) {
            CNIOLinux.timerfd_settime(fd, flags, newValue, oldValue)
        }
    }

    @inline(never)
    public static func timerfd_create(clockId: Int32, flags: Int32) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.timerfd_create(clockId, flags)
        }.result
    }
}

internal enum EventFd {
    public static let EFD_CLOEXEC = CNIOLinux.EFD_CLOEXEC
    public static let EFD_NONBLOCK = CNIOLinux.EFD_NONBLOCK
    public static let EFD_SEMAPHORE = CNIOLinux.EFD_SEMAPHORE
    public typealias eventfd_t = CNIOLinux.eventfd_t

    @inline(never)
    public static func eventfd_write(fd: Int32, value: UInt64) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.eventfd_write(fd, value)
        }.result
    }

    @inline(never)
    public static func eventfd_read(fd: Int32, value: UnsafeMutablePointer<UInt64>) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.eventfd_read(fd, value)
        }.result
    }

    @inline(never)
    public static func eventfd(initval: UInt32, flags: Int32) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.eventfd(initval, flags)
        }.result
    }
}

internal enum Epoll {
    public typealias epoll_event = CNIOLinux.epoll_event

    public static let EPOLL_CTL_ADD: CInt = numericCast(CNIOLinux.EPOLL_CTL_ADD)
    public static let EPOLL_CTL_MOD: CInt = numericCast(CNIOLinux.EPOLL_CTL_MOD)
    public static let EPOLL_CTL_DEL: CInt = numericCast(CNIOLinux.EPOLL_CTL_DEL)

    #if os(Android)
    public static let EPOLLIN: CUnsignedInt = 1 //numericCast(CNIOLinux.EPOLLIN)
    public static let EPOLLOUT: CUnsignedInt = 4 //numericCast(CNIOLinux.EPOLLOUT)
    public static let EPOLLERR: CUnsignedInt = 8 // numericCast(CNIOLinux.EPOLLERR)
    public static let EPOLLRDHUP: CUnsignedInt = 8192 //numericCast(CNIOLinux.EPOLLRDHUP)
    public static let EPOLLHUP: CUnsignedInt = 16 //numericCast(CNIOLinux.EPOLLHUP)
    public static let EPOLLET: CUnsignedInt = 2147483648 //numericCast(CNIOLinux.EPOLLET)
    #else
    public static let EPOLLIN: CUnsignedInt = numericCast(CNIOLinux.EPOLLIN.rawValue)
    public static let EPOLLOUT: CUnsignedInt = numericCast(CNIOLinux.EPOLLOUT.rawValue)
    public static let EPOLLERR: CUnsignedInt = numericCast(CNIOLinux.EPOLLERR.rawValue)
    public static let EPOLLRDHUP: CUnsignedInt = numericCast(CNIOLinux.EPOLLRDHUP.rawValue)
    public static let EPOLLHUP: CUnsignedInt = numericCast(CNIOLinux.EPOLLHUP.rawValue)
    public static let EPOLLET: CUnsignedInt = numericCast(CNIOLinux.EPOLLET.rawValue)
    #endif

    public static let ENOENT: CUnsignedInt = numericCast(CNIOLinux.ENOENT)


    @inline(never)
    public static func epoll_create(size: Int32) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.epoll_create(size)
        }.result
    }

    @inline(never)
    @discardableResult
    public static func epoll_ctl(epfd: Int32, op: Int32, fd: Int32, event: UnsafeMutablePointer<epoll_event>) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.epoll_ctl(epfd, op, fd, event)
        }.result
    }

    @inline(never)
    public static func epoll_wait(epfd: Int32, events: UnsafeMutablePointer<epoll_event>, maxevents: Int32, timeout: Int32) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.epoll_wait(epfd, events, maxevents, timeout)
        }.result
    }
}

enum UringError: Error {
    case loadFailure
    case uringSetupFailure
    case uringWaitCqeFailure
    case uringWaitCqeTimeoutFailure
}

extension StringProtocol {
    var drop0xPrefix: SubSequence { hasPrefix("0x") ? dropFirst(2) : self[...] }
    var drop0bPrefix: SubSequence { hasPrefix("0b") ? dropFirst(2) : self[...] }
    var hexaToDecimal: Int { Int(drop0xPrefix, radix: 16) ?? 0 }
    var hexaToBinary: String { .init(hexaToDecimal, radix: 2) }
    var decimalToHexa: String { .init(Int(self) ?? 0, radix: 16) }
    var decimalToBinary: String { .init(Int(self) ?? 0, radix: 2) }
    var binaryToDecimal: Int { Int(drop0bPrefix, radix: 2) ?? 0 }
    var binaryToHexa: String { .init(binaryToDecimal, radix: 16) }
}
extension BinaryInteger {
    var binary: String { .init(self, radix: 2) }
    var hexa: String { .init(self, radix: 16) }
}

extension TimeAmount {
    public func kernelTimespec() -> __kernel_timespec {
        var ts = __kernel_timespec()
        ts.tv_sec = self.nanoseconds / 1_000_000_000
        ts.tv_nsec = self.nanoseconds % 1_000_000_000
        return ts
    }
}

enum CqeEventType : Int {
    case poll = 0, pollModify, pollDelete
}

public class Uring {
    private var ring = io_uring()
    private let ring_entries: CUnsignedInt = 4096
    private let cqeCount = 1000

    // FIXME: cqeCount should be bumped to a larger value for deployment, just keeping small for debugging
    //    private let cqeCount = 10000

    public static let POLLIN: CUnsignedInt = numericCast(CNIOLinux.POLLIN)
    public static let POLLOUT: CUnsignedInt = numericCast(CNIOLinux.POLLOUT)
    public static let POLLERR: CUnsignedInt = numericCast(CNIOLinux.POLLERR)
    public static let POLLRDHUP: CUnsignedInt = numericCast(CNIOLinux.EPOLLRDHUP.rawValue) // FIXME: - POLLRDHUP not available on ubuntu headers?!
    public static let POLLHUP: CUnsignedInt = numericCast(CNIOLinux.POLLHUP)
        
    var cqes : UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>
    var fdEvents = [Int32: UInt32]() // fd : event_poll_return
    var emptyCqe = io_uring_cqe()

    func dumpCqes(_ header:String, count: Int)
    {
        if count < 0 {
            return
        }
        _debugPrint(header + " CQE:s [\(cqes)] - ring flags are [\(ring.flags)]")
        for i in 0..<count {
            let c = cqes[i]!.pointee

            let dp = io_uring_cqe_get_data(cqes[i])
            let bitPattern : UInt = UInt(bitPattern:dp)

            let fd = Int(bitPattern & 0x00000000FFFFFFFF)
            let eventType = Int(bitPattern >> 32) // shift out the fd

            let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))

            _debugPrint("\(i) = fd[\(fd)] eventType[\(CqeEventType(rawValue:eventType))] res [\(c.res)] flags [\(c.flags)]  bitpattern[\(String(describing:bitpatternAsPointer))]")
        }
    }
    
    init() {
        cqes = UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>.allocate(capacity: cqeCount)
        cqes.initialize(repeating:&emptyCqe, count:cqeCount)
    }
    
    deinit {
        cqes.deallocate()
    }
    
   @inline(never)
    public static func io_uring_load() throws -> () {
//        throw UringError.loadFailure // force epoll
            if (CNIOLinux.CNIOLinux_io_uring_load() != 0)
            {
                throw UringError.loadFailure
            }
        }

    public func fd() -> Int32 {
       return ring.ring_fd
    }

    @inline(never)
    public func io_uring_queue_init() throws -> () {
        // FIXME: IORING_SETUP_SQPOLL is basically useless in default configuraiton as it starts one kernel
        // poller thread per ring. It is possible to regulate this by sharing a kernel thread for the polling
        // with IORING_SETUP_ATTACH_WQ, but it requires the first ring to be setup with polling and then the
        // fd shared with later rings. Not very convenient or clean really. A New setup option is in the works
        // IORING_SETUP_SQPOLL_PERCPU which together with IORING_SETUP_SQ_AFF will be possible to use to
        // bind the kernel poller thread to a given cpu (and share one amongst all rings) - not yet in
        // the kernel and work in progress, but sounds like it would be a better fit and worth trying.
        // Alternatively we could look at limiting number of threads created to numcpu / 2 or so
        // instead of starting one thread per core in the multithreaded event loop
        if (CNIOLinux.CNIOLinux_io_uring_queue_init(ring_entries, &ring, 0 ) != 0) // IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL
        
         {
             throw UringError.uringSetupFailure
         }
        
        _debugPrint("uring setup \(self.ring.ring_fd)")
//        print("uring setup \(self.ring.ring_fd)")
     }
  
    public func io_uring_queue_exit() {
        _debugPrint("exit uring")
        CNIOLinux_io_uring_queue_exit(&ring)
    }

    /*
        Ok, this was a real bummer - turns out that flushing multiple SQE:s
        can fail midflight and this will actually happen when e.g. a socket
        has gone down and we are re-regsitering poll for both the socket fd
        and e.g. eventfd - this means we will silently lose any entries after the
        failed fd. Ouch. Proper approach is to use io_uring_sq_ready() in a loop.
        See: https://github.com/axboe/liburing/issues/309
    */
            
    public func io_uring_flush() {         // When using SQPOLL this is just a NOP
        _debugPrint("io_uring_flush")

        var submissiontimes = 0
        var retval : Int32
        
        // FIXME:  it may return -EAGAIN or -ENOMEM when there is not enough memory to do internal allocations.
        while (CNIOLinux_io_uring_sq_ready(&ring) > 0)
        {
            retval = CNIOLinux_io_uring_submit(&ring)
            submissiontimes += 1

            if submissiontimes > 1 {
                if (retval == -EAGAIN)
                {
//                    print("io_uring_flush io_uring_submit -EAGAIN \(submissiontimes)")

                }
                if (retval == -ENOMEM)
                {
//                    print("io_uring_flush io_uring_submit -ENOMEM \(submissiontimes)")

                }
                _debugPrint("io_uring_flush io_uring_submit needed \(submissiontimes)")
            }
        }
    }

    @inline(never)
    public func io_uring_prep_poll_add(fd: Int32, poll_mask: UInt32, submitNow: Bool = true) -> () {
        let sqe = CNIOLinux_io_uring_get_sqe(&ring)
        let bitPattern : Int = CqeEventType.poll.rawValue << 32 + Int(fd)
        let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))

        _debugPrint("io_uring_prep_poll_add poll_mask[\(poll_mask)] fd[\(fd)] sqe[\(String(describing:sqe))] bitpatternAsPointer[\(String(describing:bitpatternAsPointer))] submitNow[\(submitNow)]")

        CNIOLinux.io_uring_prep_poll_add(sqe, fd, poll_mask)
        CNIOLinux.io_uring_sqe_set_data(sqe, bitpatternAsPointer) // must be done after prep_poll_add, otherwise zeroed out.

        sqe!.pointee.len |= IORING_POLL_ADD_MULTI;

        if submitNow {
            io_uring_flush()
        }
    }
    
    @inline(never)
    public func io_uring_prep_poll_remove(fd: Int32, poll_mask: UInt32, submitNow: Bool = true) -> () {
        let sqe = CNIOLinux_io_uring_get_sqe(&ring)

        let bitPattern : Int = CqeEventType.poll.rawValue << 32 + Int(fd)
        let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))

        _debugPrint("io_uring_prep_poll_remove poll_mask[\(poll_mask)] fd[\(fd)] sqe[\(String(describing:sqe))] bitpatternAsPointer[\(String(describing:bitpatternAsPointer))] submitNow[\(submitNow)]")

        CNIOLinux.io_uring_prep_poll_remove(sqe, bitpatternAsPointer)
        CNIOLinux.io_uring_sqe_set_data(sqe, bitpatternAsPointer) // must be done after prep_poll_add, otherwise zeroed out.

        if submitNow {
            io_uring_flush()
        }
    }

    @inline(never)
    public func io_uring_poll_update(fd: Int32, newPollmask: UInt32, oldPollmask: UInt32, submitNow: Bool = true) -> () {

        let sqe = CNIOLinux_io_uring_get_sqe(&ring)

        let oldBitpattern : Int = CqeEventType.poll.rawValue << 32 + Int(fd)
        let newBitpattern : Int = CqeEventType.poll.rawValue << 32 + Int(fd)

        let userbitPattern : Int = CqeEventType.pollModify.rawValue << 32 + Int(fd)

        let oldBitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(oldBitpattern))
        let userBitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(userbitPattern))

        _debugPrint("io_uring_poll_update fd[\(fd)] oldPollmask[\(oldPollmask)] newPollmask[\(newPollmask)] oldBitpatternAsPointer[\(String(describing:oldBitpatternAsPointer))] userBitpatternAsPointer[\(String(describing:userBitpatternAsPointer))]")

        CNIOLinux.io_uring_prep_poll_add(sqe, fd, 0)
        sqe!.pointee.len |= IORING_POLL_ADD_MULTI       // ask for multiple updates
        sqe!.pointee.len |= IORING_POLL_UPDATE_EVENTS   // update existing mask
        sqe!.pointee.len |= IORING_POLL_UPDATE_USER_DATA // and update user data
        sqe!.pointee.addr = UInt64(oldBitpattern) // old user_data
        sqe!.pointee.off = UInt64(newBitpattern) // new user_data
        CNIOLinux.io_uring_sqe_set_data(sqe, userBitpatternAsPointer)
        sqe!.pointee.poll_events = UInt16(newPollmask) // new poll mask

        if submitNow {
            io_uring_flush()
        }
    }

    func getEnvironmentVar(_ name: String) -> String? {
        guard let rawValue = getenv(name) else { return nil }
        return String(validatingUTF8: rawValue)
    }

    public func _debugPrint(_ s:String)
    {
        if getEnvironmentVar("NIO_LINUX") != nil {
            print("L [\(NIOThread.current)] " + s)
        }
    }
    
    @inline(never)
    public func io_uring_peek_batch_cqe(events: inout [(Int32, UInt32)]) -> Int {
        _debugPrint("io_uring_peek_batch_cqe")
        let currentCqeCount = CNIOLinux_io_uring_peek_batch_cqe(&ring, cqes, UInt32(cqeCount))

        if currentCqeCount == 0 {
            return 0
        }
        
        dumpCqes("io_uring_peek_batch_cqe", count: Int(currentCqeCount))

        assert(currentCqeCount >= 0, "currentCqeCount should never be negative")
        for i in 0 ..< currentCqeCount
        {
            let bitPattern : UInt = UInt(bitPattern:io_uring_cqe_get_data(cqes[Int(i)]))
            let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
            let eventType = CqeEventType(rawValue:Int(bitPattern) >> 32) // shift out the fd
            let result = cqes[Int(i)]!.pointee.res

//            _debugPrint("io_uring_peek_batch_cqe poll_mask[\(poll_mask)] fd[\(fd)] bitpattern[\(bitPattern)] currentCqeCount [\(currentCqeCount)] result [\(result)]")
            switch eventType {
                case .poll:
                    switch result {
                        case -ECANCELED: // -ECANCELED for streaming polls, should signal error
                            let pollError = (Uring.POLLHUP | Uring.POLLERR)
                            if let current = fdEvents[fd] {
                                fdEvents[fd] = current | pollError
                            } else {
                                fdEvents[fd] = pollError
                            }
                            break
                        case -ENOENT:    // -ENOENT returned for failed poll remove
                            break
                        case -EINVAL:
                            _debugPrint("Failed with -EINVAL for i[\(i)]")
                            break
                        case -EBADF:
                            break
                        case ..<0: // other errors
                            break
                        case 0: // successfull chained add, not an event
                            break
                        default: // positive success
                            assert(bitPattern > 0, "Bitpattern should never be zero")

                            // _debugPrint("io_uring_peek_batch_cqe bitPattern[" + String(bitPattern).decimalToHexa + "]  bit[\(bitPattern)] fd[\(fd)] i[\(i)] poll_mask[\(poll_mask)] currentCqeCount[\(currentCqeCount)]")
                            let uresult = UInt32(result)
                            if let current = fdEvents[fd] {
                                fdEvents[fd] =  current | uresult
                            } else {
                                fdEvents[fd] = uresult
                            }
//                            events.append((fd, uresult)) // this
                    }
                case .pollDelete:
                    break
                case .pollModify:
                    break
                default:
                    assertionFailure("Unknown type")
            }
            
        }

        io_uring_cq_advance(&ring, currentCqeCount) // bulk variant of io_uring_cqe_seen(&ring, dataPointer)
//        io_uring_flush() // and flush any new poll adds if needed, good to advance cq first to make room

        // merge all events and actual poll_mask to return
        for (fd, result_mask) in fdEvents {

            let socketClosing = (result_mask & (Uring.POLLRDHUP | Uring.POLLHUP | Uring.POLLERR)) > 0 ? true : false

            if (socketClosing == true) {
                    _debugPrint("socket is going down [\(fd)] [\(result_mask)] [\((result_mask & (Uring.POLLRDHUP | Uring.POLLHUP | Uring.POLLERR)))]")
            }
            events.append((fd, result_mask)) // THAT
        }

        if events.count > 0 {
            _debugPrint("io_uring_peek_batch_cqe returning [\(events.count)] fdEvents [\(fdEvents)]")
        } else if fdEvents.count > 0 {
            _debugPrint("fdEvents.count > 0 but 0 event.count returning [\(events.count)] fdEvents [\(fdEvents)]")
        }

        fdEvents.removeAll(keepingCapacity: true) // reused for next batch
    
        return events.count
    }

    @inline(never)
    public func io_uring_wait_cqe(events: inout [(Int32, UInt32)]) throws -> Int {
        _debugPrint("io_uring_wait_cqe")
        let error = CNIOLinux_io_uring_wait_cqe(&ring, cqes)
        _debugPrint("CNIOLinux_io_uring_wait_cqe done [\(error)]")

        if (error == 0)
        {
//            dumpCqes("io_uring_wait_cqe")
            let bitPattern : UInt = UInt(bitPattern:io_uring_cqe_get_data(cqes[0]))
            let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
            let poll_mask = UInt32(bitPattern >> 32) // shift out the fd
            let result = cqes[0]!.pointee.res

            assert(bitPattern > 0, "Bitpattern should never be zero")

            if (result > 0) {
                _debugPrint("io_uring_wait_cqe poll_mask[\(poll_mask)] fd[\(fd)] bitPattern[\(bitPattern)]  cqes[0]!.pointee.res[\(String(describing:cqes[0]!.pointee.res))]")

                events.append((fd, UInt32(cqes[0]!.pointee.res)))
            } else {
                _debugPrint("io_uring_wait_cqe non-positive result poll_mask[\(poll_mask)] fd[\(fd)] bitPattern[\(bitPattern)] cqes[0]!.pointee.res[\(String(describing:cqes[0]!.pointee.res))]")
            }
            CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])
        }
        else
        {
            if (error == -CNIOLinux.EINTR) // we can get EINTR normally
            {
                _debugPrint("UringError.error \(error)")
            } else
            {
                _debugPrint("UringError.uringWaitCqeFailure \(error)")
                throw UringError.uringWaitCqeFailure
            }
        }
        
        return events.count
    }

    @inline(never)
    public func io_uring_wait_cqe_timeout(events: inout [(Int32, UInt32)], timeout: TimeAmount) throws -> Int {
        var ts = timeout.kernelTimespec()

        _debugPrint("io_uring_wait_cqe_timeout.ETIME milliseconds \(ts)")

        let error = CNIOLinux_io_uring_wait_cqe_timeout(&ring, cqes, &ts)

        switch error {
            case 0:
//                dumpCqes("io_uring_wait_cqe_timeout")
                let bitPattern : UInt = UInt(bitPattern:io_uring_cqe_get_data(cqes[0]))
                let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
                let poll_mask = UInt32(bitPattern >> 32) // shift out the fd
                let result = cqes[0]!.pointee.res
                if (result > 0) {
                    _debugPrint("io_uring_wait_cqe_timeout poll_mask[\(poll_mask)] fd[\(fd)] bitPattern[\(bitPattern)] cqes[0]!.pointee.res[\(String(describing:cqes[0]!.pointee.res))]")

                    events.append((fd, UInt32(cqes[0]!.pointee.res)))
                } else {
                    _debugPrint("io_uring_wait_cqe_timeout non-positive result poll_mask[\(poll_mask)] fd[\(fd)] bitPattern[\(bitPattern)] cqes[0]!.pointee.res[\(String(describing:cqes[0]!.pointee.res))]")
                }
                
                CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])
            case -CNIOLinux.ETIME: // timed out
//                _debugPrint("-CNIOLinux.ETIME")
                CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])
                return 0
            case -CNIOLinux.EINTR:
                break
            default:
                throw UringError.uringWaitCqeTimeoutFailure
        }
        
        return events.count
    }
}

internal enum Linux {
    static let cfsQuotaPath = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    static let cfsPeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
    static let cpuSetPath = "/sys/fs/cgroup/cpuset/cpuset.cpus"
#if os(Android)
    static let SOCK_CLOEXEC = Glibc.SOCK_CLOEXEC
    static let SOCK_NONBLOCK = Glibc.SOCK_NONBLOCK
#else
    static let SOCK_CLOEXEC = CInt(bitPattern: Glibc.SOCK_CLOEXEC.rawValue)
    static let SOCK_NONBLOCK = CInt(bitPattern: Glibc.SOCK_NONBLOCK.rawValue)
#endif
    @inline(never)
    public static func accept4(descriptor: CInt,
                               addr: UnsafeMutablePointer<sockaddr>?,
                               len: UnsafeMutablePointer<socklen_t>?,
                               flags: CInt) throws -> CInt? {
        guard case let .processed(fd) = try syscall(blocking: true, {
            CNIOLinux.CNIOLinux_accept4(descriptor, addr, len, flags)
        }) else {
          return nil
        }
        return fd
    }

    private static func firstLineOfFile(path: String) throws -> Substring {
        let fh = try NIOFileHandle(path: path)
        defer { try! fh.close() }
        // linux doesn't properly report /sys/fs/cgroup/* files lengths so we use a reasonable limit
        var buf = ByteBufferAllocator().buffer(capacity: 1024)
        try buf.writeWithUnsafeMutableBytes(minimumWritableBytes: buf.capacity) { ptr in
            let res = try fh.withUnsafeFileDescriptor { fd -> IOResult<ssize_t> in
                return try Posix.read(descriptor: fd, pointer: ptr.baseAddress!, size: ptr.count)
            }
            switch res {
            case .processed(let n):
                return n
            case .wouldBlock:
                preconditionFailure("read returned EWOULDBLOCK despite a blocking fd")
            }
        }
        return String(buffer: buf).prefix(while: { $0 != "\n" })
    }

    private static func countCoreIds(cores: Substring) -> Int {
        let ids = cores.split(separator: "-", maxSplits: 1)
        guard
            let first = ids.first.flatMap({ Int($0, radix: 10) }),
            let last = ids.last.flatMap({ Int($0, radix: 10) }),
            last >= first
        else { preconditionFailure("cpuset format is incorrect") }
        return 1 + last - first
    }

    static func coreCount(cpuset cpusetPath: String) -> Int? {
        guard
            let cpuset = try? firstLineOfFile(path: cpusetPath).split(separator: ","),
            !cpuset.isEmpty
        else { return nil }
        return cpuset.map(countCoreIds).reduce(0, +)
    }

    static func coreCount(quota quotaPath: String,  period periodPath: String) -> Int? {
        guard
            let quota = try? Int(firstLineOfFile(path: quotaPath)),
            quota > 0
        else { return nil }
        guard
            let period = try? Int(firstLineOfFile(path: periodPath)),
            period > 0
        else { return nil }
        return (quota - 1 + period) / period // always round up if fractional CPU quota requested
    }
}
#endif
