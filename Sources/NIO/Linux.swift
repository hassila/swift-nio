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
    public static func eventfd(initval: Int32, flags: Int32) throws -> Int32 {
        return try syscall(blocking: false) {
            CNIOLinux.eventfd(0, Int32(EFD_CLOEXEC | EFD_NONBLOCK))
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
    case eventFDregistrationFailure
    case uringWaitCqeFailure
    case uringWaitCqeTimeoutFailure
}
/*
extension Uring: Sequence {

    func makeIterator() -> FDIterator {
        return FDIterator(self)
    }
}

class FDIterator: IteratorProtocol {

    private let collection: UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>
    private var index = 0

    init(_ collection: UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>) {
        self.collection = collection
    }

    func next() -> String? {
        defer { index += 1 }
        return index < collection.items.count ? collection.items[index] : nil
    }
}
*/

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

public class Uring {
    private var ring = io_uring()
    private let ring_entries: CUnsignedInt = 4096
    private var iteratorIndex: Int?

    public static let POLLIN: CUnsignedInt = numericCast(CNIOLinux.POLLIN)
    public static let POLLOUT: CUnsignedInt = numericCast(CNIOLinux.POLLOUT)
    public static let POLLERR: CUnsignedInt = numericCast(CNIOLinux.POLLERR)
    public static let POLLRDHUP: CUnsignedInt = numericCast(CNIOLinux.EPOLLRDHUP.rawValue) // FIXME: - POLLRDHUP not available on ubuntu headers?!
    public static let POLLHUP: CUnsignedInt = numericCast(CNIOLinux.POLLHUP)

    let cqeCount = 10
    var cqes : UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>
    var emptyCqe = io_uring_cqe()
    
    func dumpCqes(_ header:String)
    {
        _debugPrint(header + " CQE:s [\(cqes)]")
        for i in 0..<cqeCount {
            let c = cqes[i]!.pointee

            let dp = io_uring_cqe_get_data(cqes[i])
            let bitPattern : UInt = UInt(bitPattern:dp)

            let fd = Int(bitPattern & 0x00000000FFFFFFFF)
            let poll_mask = Int(bitPattern >> 32) // shift out the fd

            _debugPrint("\(i) = \(String(describing:cqes[i])) | user_data [\(c.user_data)] res [\(c.res)] flags [\(c.flags)] fd[\(fd)] poll_mask[\(poll_mask)]")
        }
    }
    init() {
        cqes = UnsafeMutablePointer<UnsafeMutablePointer<io_uring_cqe>?>.allocate(capacity: cqeCount)
        cqes.initialize(repeating:&emptyCqe, count:cqeCount)
//        dumpCqes("init")
    }
    
    deinit {
        cqes.deallocate()
    }
    
   @inline(never)
    public static func io_uring_load() throws -> () {
//        throw UringError.loadFailure
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
        if (CNIOLinux.CNIOLinux_io_uring_queue_init(ring_entries, &ring, 0 ) != 0) // IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL
        
         {
             throw UringError.uringSetupFailure
         }
        _debugPrint("uring setup \(self.ring.ring_fd)")
     }
    
    @inline(never)
    public func io_uring_register_eventfd(fd: Int32) throws -> () {
        _debugPrint("CNIOLinux_io_uring_register_eventfd \(fd)")
/*        if (CNIOLinux.CNIOLinux_io_uring_register_eventfd(&ring, fd) != 0)
         {
             throw UringError.eventFDregistrationFailure
         }
 */   }
        
    public func _io_uring_prep_poll_add_prep(fd: Int32, poll_mask: UInt32) -> () {
        let sqe = CNIOLinux_io_uring_get_sqe(&ring)
        let bitPattern : Int = Int(Int(poll_mask) << 32) + Int(fd) // stuff poll_mask in upper 4 bytes
        let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))
        _debugPrint("io_uring_prep_poll_add bitPattern[" + String(bitPattern).decimalToHexa + "] bit[\(bitPattern)] poll_mask[\(poll_mask)] fd[\(fd)] sqe[\(String(describing:sqe))] bitpatternAsPointer[\(String(describing:bitpatternAsPointer))]")

        CNIOLinux.io_uring_prep_poll_add(sqe, fd, poll_mask)
        CNIOLinux.io_uring_sqe_set_data(sqe, bitpatternAsPointer) // must be done after prep_poll_add, otherwise zeroed out.
//        CNIOLinux_io_uring_submit(&ring)
    }
    
    @inline(never)
    public func io_uring_prep_poll_add(fd: Int32, poll_mask: UInt32) -> () {
        self._io_uring_prep_poll_add_prep(fd: fd, poll_mask: poll_mask)
        CNIOLinux_io_uring_submit(&ring)
    }

    @inline(never)
    public func _io_uring_prep_poll_remove_prep(fd: Int32, poll_mask: UInt32) -> () {
        let sqe = CNIOLinux_io_uring_get_sqe(&ring)
        let bitPattern : Int = Int(Int(poll_mask) << 32) + Int(fd) // stuff poll_mask in upper 4 bytes
        let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))
        _debugPrint("io_uring_prep_poll_remove bitPattern[" + String(bitPattern).decimalToHexa + "] bit[\(bitPattern)] poll_mask[\(poll_mask)] fd[\(fd)] sqe[\(String(describing:sqe))] bitpatternAsPointer[\(String(describing:bitpatternAsPointer))]")

        CNIOLinux.io_uring_prep_poll_remove(sqe, bitpatternAsPointer)
        CNIOLinux.io_uring_sqe_set_data(sqe, bitpatternAsPointer) // must be done after prep_poll_add, otherwise zeroed out.
    }

    @inline(never)
    public func io_uring_prep_poll_change(fd: Int32, poll_mask: UInt32) -> () {
/*        let sqe = CNIOLinux_io_uring_get_sqe(&ring)
        let bitPattern : Int = Int(Int(poll_mask) << 32) + Int(fd) // stuff poll_mask in upper 4 bytes
        let bitpatternAsPointer = UnsafeMutableRawPointer.init(bitPattern: UInt(bitPattern))
         _debugPrint("io_uring_prep_poll_remove bitPattern[" + String(bitPattern).decimalToHexa + "] bit[\(bitPattern)] poll_mask[\(poll_mask)] fd[\(fd)] sqe[\(String(describing:sqe))] bitpatternAsPointer[\(String(describing:bitpatternAsPointer))]")

        CNIOLinux.io_uring_prep_poll_remove(sqe, bitpatternAsPointer)
        CNIOLinux_io_uring_submit(&ring) */

    }
    
    @inline(never)
    public func io_uring_prep_poll_remove(fd: Int32, poll_mask: UInt32) -> () {
        self._io_uring_prep_poll_remove_prep(fd: fd, poll_mask: poll_mask)
        CNIOLinux_io_uring_submit(&ring)
    }

    func _debugPrint(_ string : String) -> ()  {
        print(string)
    }
    
    @inline(never)
    public func io_uring_peek_batch_cqe(events: inout [(Int32, UInt32)]) -> Int {
print("io_uring_peek_batch_cqe")
        var fdEvents = [Int32: (UInt32, UInt32)]() // fd : original_poll_mask, event_poll_return
print("io_uring_peek_batch_cqe2")
        let currentCqeCount = CNIOLinux_io_uring_peek_batch_cqe(&ring, cqes, UInt32(cqeCount));
        print("io_uring_peek_batch_cqe211")

        if (currentCqeCount > 0) {
            dumpCqes("io_uring_peek_batch_cqe res0 [\(UInt32(cqes[0]!.pointee.res))]")
        }
        print("io_uring_peek_batch_cqe212")

        for i in 0 ..< currentCqeCount
        {
            print("io_uring_peek_batch_cqe213")

            let dataPointer = cqes[Int(i)]
            print("io_uring_peek_batch_cqe21")
            let result = cqes[Int(i)]!.pointee.res
            print("io_uring_peek_batch_cqe22")
            if (result > 0) {

                let dp = io_uring_cqe_get_data(dataPointer)
                let bitPattern : UInt = UInt(bitPattern:dp)
                let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
                let poll_mask = UInt32(bitPattern >> 32) // shift out the fd
                
                _debugPrint("io_uring_peek_batch_cqe bitPattern[" + String(bitPattern).decimalToHexa + "]  bit[\(bitPattern)] fd[\(fd)] i[\(i)] poll_mask[\(poll_mask)] currentCqeCount[\(currentCqeCount)] dp[\(String(describing:dp))] dataPointer[\(String(describing:dataPointer))] cqes[Int(i)][\(String(describing:cqes[Int(i)]))] cqes[\(String(describing:cqes))]")

                if (result >= 0)
                {
                    let uresult = UInt32(result)
                    if let current = fdEvents[fd] {
                        _debugPrint("masking in \(current), (\(poll_mask), \(result))")
                        fdEvents[fd] = ((current.0 | poll_mask), (current.1 | uresult))
                        _debugPrint("masked in \(fdEvents[fd])")
                    } else
                    {
                        fdEvents[fd] = (poll_mask, uresult)
                    }
                }

                _debugPrint("result is \(result) \(fdEvents[fd])")
                CNIOLinux.io_uring_cqe_seen(&ring, dataPointer)
                withUnsafeMutablePointer( to: &emptyCqe) { cqes[Int(i)] = $0 }

            } else
            {
                CNIOLinux.io_uring_cqe_seen(&ring, dataPointer)
                withUnsafeMutablePointer( to: &emptyCqe) { cqes[Int(i)] = $0 }
                _debugPrint("zero or negative return, result is \(result)")
            }
        }

        if (currentCqeCount > 5)
        {
            _debugPrint("break here")
        }
//        io_uring_cq_advance(&ring, currentCqeCount); // bulk variant of CNIOLinux.io_uring_cqe_seen(&ring, dataPointer)

//        cqes.initialize(repeating:&emptyCqe, count:cqeCount)
//        dumpCqes("cqes.initialize")
        // merge all events and actual poll_mask
        for (fd, (poll_mask, result_mask)) in fdEvents {
            _debugPrint("append (\(fd),\(result_mask)) reregister \(poll_mask)")
            let socketClosing = (result_mask & (Uring.POLLRDHUP | Uring.POLLHUP | Uring.POLLERR)) > 0 ? true : false
            _debugPrint("1111111")

            if (socketClosing == false) {
                _debugPrint("222222")
                self._io_uring_prep_poll_add_prep(fd: fd, poll_mask: poll_mask) // requires an io_uring_submit later
                _debugPrint("333333")
            } else
            {
                _debugPrint("444444")
                _debugPrint("socket is going down \((result_mask & (Uring.POLLRDHUP | Uring.POLLHUP | Uring.POLLERR)))")
                _debugPrint("555555")
            }
            _debugPrint("6666666")
            events.append((fd, result_mask))
            _debugPrint("777777")
        }
        CNIOLinux_io_uring_submit(&ring)
print("events.count \(events.count)")
        return events.count
    }

    @inline(never)
    public func io_uring_wait_cqe(events: inout [(Int32, UInt32)]) throws -> Int {
//        _debugPrint("io_uring_wait_cqe before cqes[0][\(String(describing:cqes[0]))]")
        _debugPrint("io_uring_wait_cqe")
        let error = CNIOLinux_io_uring_wait_cqe(&ring, cqes)
        dumpCqes("io_uring_wait_cqe")
        if (error == 0)
        {
            dumpCqes("io_uring_wait_cqe")
            let bitPattern : UInt = UInt(bitPattern:io_uring_cqe_get_data(cqes[0]))
            let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
            let poll_mask = UInt32(bitPattern >> 32) // shift out the fd
            _debugPrint("io_uring_wait_cqe bitPattern[" + String(bitPattern).decimalToHexa + "]  bit[\(bitPattern)] fd[\(fd)] poll_mask[\(poll_mask)]")
            events.append((fd, UInt32(cqes[0]!.pointee.res)))
            CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])
            self.io_uring_prep_poll_add(fd: fd, poll_mask: poll_mask)
            withUnsafeMutablePointer( to: &emptyCqe) { cqes[0] = $0 }

        }
        else
        {
            _debugPrint("\(error)")
            throw UringError.uringWaitCqeFailure
        }
        
//        cqes.initialize(repeating:&emptyCqe, count:cqeCount)
//        dumpCqes("cqes.initialize")

        return 1
    }

    @inline(never)
    public func io_uring_wait_cqe_timeout(events: inout [(Int32, UInt32)], timeout: TimeAmount) throws -> Int {
        _debugPrint("io_uring_wait_cqe_timeout")
        var ts = __kernel_timespec()
        ts.tv_sec = 0
        ts.tv_nsec = timeout.nanoseconds
//        _debugPrint("io_uring_wait_cqe_timeout before cqes[0][\(String(describing:cqes[0]))]")
//        dumpCqes("io_uring_wait_cqe_timeout before")

        let error = CNIOLinux_io_uring_wait_cqe_timeout(&ring, cqes, &ts)

        switch error {
            case 0:
                dumpCqes("io_uring_wait_cqe_timeout")
                let bitPattern : UInt = UInt(bitPattern:io_uring_cqe_get_data(cqes[0]))
                let fd = Int32(bitPattern & 0x00000000FFFFFFFF)
                let poll_mask = UInt32(bitPattern >> 32) // shift out the fd
                let result = cqes[0]!.pointee.res
                if (result > 0) {

                    _debugPrint("io_uring_wait_cqe_timeout bitPattern[" + String(bitPattern).decimalToHexa + "]  bit[\(bitPattern)] fd[\(fd)] poll_mask[\(poll_mask)] cqes[0][\(String(describing:cqes[0]))] cqes[0]!.pointee.res[\(String(describing:cqes[0]!.pointee.res))]")
                    events.append((fd, UInt32(cqes[0]!.pointee.res)))
                    self.io_uring_prep_poll_add(fd: fd, poll_mask: poll_mask)
                } else
                {
                    _debugPrint("io_uring_wait_cqe_timeout result [\(result)]")
                }
                CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])

                withUnsafeMutablePointer( to: &emptyCqe) { cqes[0] = $0 }

            case -CNIOLinux.ETIME: // timed out
                _debugPrint("-CNIOLinux.ETIME")
                withUnsafeMutablePointer( to: &emptyCqe) { cqes[0] = $0 }
                CNIOLinux.io_uring_cqe_seen(&ring, cqes[0])
                return 0
            default:
                throw UringError.uringWaitCqeTimeoutFailure
        }
        
//        cqes.initialize(repeating:&emptyCqe, count:cqeCount)
//        dumpCqes("cqes.initialize")

        return 1
    }

    @inline(never)
    public func io_uring_wakeup() -> () {
        return
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
