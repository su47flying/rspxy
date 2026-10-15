//! Platform-specific UDP socket options (Linux and Windows).

use std::io;

use socket2::SockRef;

/// Sets DF on outgoing packets and ignores the cached path MTU, so QUIC's own
/// MTU discovery sees the real path (the SSU socket reports `may_fragment() == false`).
/// Errors are ignored: the IPv6 option fails on an IPv4 socket and vice versa.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_dont_fragment<'s>(sock: impl Into<SockRef<'s>>) {
    use std::os::fd::AsRawFd;
    let fd = sock.into().as_raw_fd();
    let v4: libc::c_int = libc::IP_PMTUDISC_PROBE;
    let v6: libc::c_int = libc::IPV6_PMTUDISC_PROBE;
    // SAFETY: plain setsockopt on a valid fd with correctly sized int values.
    unsafe {
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            (&v4 as *const libc::c_int).cast(),
            sz,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            (&v6 as *const libc::c_int).cast(),
            sz,
        );
    }
}

/// Sets DF on outgoing packets and ignores the cached path MTU, so QUIC's own
/// MTU discovery sees the real path (the SSU socket reports `may_fragment() == false`).
/// Errors are ignored: the IPv6 option fails on an IPv4 socket and vice versa.
#[cfg(windows)]
pub fn set_dont_fragment<'s>(sock: impl Into<SockRef<'s>>) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        IP_DONTFRAGMENT, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG,
        IPV6_MTU_DISCOVER, SOCKET, setsockopt,
    };
    let s = sock.into().as_raw_socket() as SOCKET;
    // SAFETY: plain setsockopt on a valid socket with a correctly sized int value.
    let set = |level, opt, v: i32| unsafe { setsockopt(s, level, opt, (&v as *const i32).cast(), 4) == 0 };
    for (level, discover, dont_frag) in [
        (IPPROTO_IP, IP_MTU_DISCOVER, IP_DONTFRAGMENT),
        (IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_DONTFRAG),
    ] {
        // IP_MTU_DISCOVER is missing before Windows 10 1703; fall back to the plain DF flag.
        if !set(level, discover, IP_PMTUDISC_PROBE) {
            set(level, dont_frag, 1);
        }
    }
}

/// Windows reports an ICMP port unreachable for an earlier `send_to` as
/// WSAECONNRESET on the socket's next `recv_from`, so one closed client port
/// would end a UDP relay loop. SIO_UDP_CONNRESET turns that off, as
/// shadowsocks-rust does. Linux only reports it on connected sockets.
#[cfg(windows)]
pub fn disable_udp_connreset<'s>(sock: impl Into<SockRef<'s>>) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl};
    let s = sock.into().as_raw_socket() as SOCKET;
    let enable: i32 = 0; // BOOL FALSE
    let mut returned = 0u32;
    // SAFETY: synchronous WSAIoctl on a valid socket with a BOOL input and no output buffer.
    let ret = unsafe {
        WSAIoctl(
            s,
            SIO_UDP_CONNRESET,
            (&enable as *const i32).cast(),
            std::mem::size_of_val(&enable) as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if ret == SOCKET_ERROR {
        // SAFETY: no preconditions.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn disable_udp_connreset<'s>(_sock: impl Into<SockRef<'s>>) -> io::Result<()> {
    Ok(())
}

/// Raises the soft open-file limit to the hard limit, as Go does at startup.
/// Each proxied connection holds one or two descriptors, so the usual soft
/// default of 1024 runs out under a browser's load and accept() fails with EMFILE.
#[cfg(unix)]
pub fn raise_nofile_limit() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit with a valid, initialised rlimit.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 || lim.rlim_cur >= lim.rlim_max {
            return;
        }
        let old = lim.rlim_cur;
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0 {
            tracing::debug!("open file limit raised from {old} to {}", lim.rlim_cur);
        }
    }
}

#[cfg(not(unix))]
pub fn raise_nofile_limit() {}
