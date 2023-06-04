pub const c = @cImport({
    @cDefine("struct_XSTAT", ""); // fix error
    @cInclude("wolfssl/wolfcrypt/settings.h");
    @cInclude("wolfssl/ssl.h");
});
pub const crypto = @import("std").crypto;
pub const tls = @import("std").crypto.tls;

const WolfSSL = @This();

// fields
ctx: ?*c.WOLFSSL_CTX,
ssl: ?*c.WOLFSSL,

pub const tlsMethod = enum {
    TLSv1_2Client,
    TLSv1_2Server,
    TLSv1_1Client,
    TLSv1_1Server,
};

pub fn init(method: tlsMethod) !WolfSSL {
    try checkError(c.wolfSSL_Init());
    const tls_method = switch (method) {
        .TLSv1_1Client => c.wolfTLSv1_1_client_method(),
        .TLSv1_2Client => c.wolfTLSv1_2_client_method(),
        .TLSv1_1Server => c.wolfTLSv1_1_server_method(),
        .TLSv1_2Server => c.wolfTLSv1_2_server_method(),
    };
    var wolf: WolfSSL = undefined;
    wolf.ctx = c.wolfSSL_CTX_new(tls_method) orelse return error.WolfSSL_CTX;
    wolf.ssl = c.wolfSSL_new(wolf.ctx) orelse return error.WolfSSL;
    return wolf;
}
pub fn connect(self: *WolfSSL) !void {
    try checkError(c.wolfSSL_connect(self.ssl));
}
pub fn shutdown(self: *WolfSSL) !void {
    try checkError(c.wolfSSL_shutdown(self.ssl));
}
pub fn deinit(self: *WolfSSL) !void {
    c.wolfSSL_free(self.ssl);
    c.wolfSSL_CTX_free(self.ctx);
    try checkError(c.wolfSSL_Cleanup());
}

fn checkError(err_code: c_int) WolfSSLError!void {
    return switch (err_code) {
        c.WOLFSSL_FAILURE => error.wolfsslFailure,
        // c.WOLFSSL_SHUTDOWN_NOT_DONE => error.wolfsslShutdownNotDone,
        c.WOLFSSL_ALPN_NOT_FOUND => error.wolfsslAlpnNotFound,
        c.WOLFSSL_BAD_CERTTYPE => error.wolfsslBadCerttype,
        c.WOLFSSL_BAD_STAT => error.wolfsslBadStat,
        c.WOLFSSL_BAD_PATH => error.wolfsslBadPath,
        c.WOLFSSL_BAD_FILETYPE => error.wolfsslBadFiletype,
        c.WOLFSSL_BAD_FILE => error.wolfsslBadFile,
        c.WOLFSSL_NOT_IMPLEMENTED => error.wolfsslNotImplemented,
        c.WOLFSSL_UNKNOWN => error.wolfsslUnknown,
        c.WOLFSSL_FATAL_ERROR => error.wolfsslFatalError,
        // c.WOLFSSL_VERIFY_PEER => error.wolfsslVerifyPeer,
        // c.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT => error.wolfsslVerifyFailIfNoPeerCert,
        // c.WOLFSSL_VERIFY_CLIENT_ONCE => error.wolfsslVerifyClientOnce,
        // c.WOLFSSL_VERIFY_POST_HANDSHAKE => error.wolfsslVerifyPostHandshake,
        // c.WOLFSSL_VERIFY_FAIL_EXCEPT_PSK => error.wolfsslVerifyFailExceptPsk,
        // c.WOLFSSL_VERIFY_DEFAULT => error.wolfsslVerifyDefault,
        // c.WOLFSSL_SESS_CACHE_OFF => error.wolfsslSessCacheOff,
        // c.WOLFSSL_SESS_CACHE_CLIENT => error.wolfsslSessCacheClient,
        // c.WOLFSSL_SESS_CACHE_SERVER => error.wolfsslSessCacheServer,
        // c.WOLFSSL_SESS_CACHE_BOTH => error.wolfsslSessCacheBoth,
        // c.WOLFSSL_SESS_CACHE_NO_AUTO_CLEAR => error.wolfsslSessCacheNoAutoClear,
        // c.WOLFSSL_SESS_CACHE_NO_INTERNAL_LOOKUP => error.wolfsslSessCacheNoInternalLookup,
        // c.WOLFSSL_SESS_CACHE_NO_INTERNAL_STORE => error.wolfsslSessCacheNoInternalStore,
        // c.WOLFSSL_SESS_CACHE_NO_INTERNAL => error.wolfsslSessCacheNoInternal,
        // c.WOLFSSL_ERROR_WANT_READ => error.wolfsslErrorWantRead,
        // c.WOLFSSL_ERROR_WANT_WRITE => error.wolfsslErrorWantWrite,
        // c.WOLFSSL_ERROR_WANT_CONNECT => error.wolfsslErrorWantConnect,
        // c.WOLFSSL_ERROR_WANT_ACCEPT => error.wolfsslErrorWantAccept,
        c.WOLFSSL_ERROR_SYSCALL => error.wolfsslErrorSyscall,
        c.WOLFSSL_ERROR_WANT_X509_LOOKUP => error.wolfsslErrorWantX509Lookup,
        c.WOLFSSL_ERROR_ZERO_RETURN => error.wolfsslErrorZeroReturn,
        c.WOLFSSL_ERROR_SSL => error.wolfsslErrorSsl,
        // c.WOLFSSL_SENT_SHUTDOWN => error.wolfsslSentShutdown,
        // c.WOLFSSL_RECEIVED_SHUTDOWN => error.wolfsslReceivedShutdown,
        c.WOLFSSL_MODE_ACCEPT_MOVING_WRITE_BUFFER => error.wolfsslModeAcceptMovingWriteBuffer,
        c.WOLFSSL_R_SSL_HANDSHAKE_FAILURE => error.wolfsslRsslHandshakeFailure,
        c.WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA => error.wolfsslRtlsv1AlertUnknownCa,
        c.WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN => error.wolfsslRsslv3AlertCertificateUnknown,
        c.WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE => error.wolfsslRsslv3AlertBadCertificate,
        c.WOLFSSL_SUCCESS => {},
        else => return,
    };
}

const WolfSSLError = error{
    // wolfsslErrorNone,
    wolfsslFailure,
    wolfsslShutdownNotDone,
    wolfsslAlpnNotFound,
    wolfsslBadCerttype,
    wolfsslBadStat,
    wolfsslBadPath,
    wolfsslBadFiletype,
    wolfsslBadFile,
    wolfsslNotImplemented,
    wolfsslUnknown,
    wolfsslFatalError,
    wolfsslFiletypeAsn1,
    wolfsslFiletypePem,
    wolfsslFiletypeDefault,
    wolfsslVerifyNone,
    wolfsslVerifyPeer,
    wolfsslVerifyFailIfNoPeerCert,
    wolfsslVerifyClientOnce,
    wolfsslVerifyPostHandshake,
    wolfsslVerifyFailExceptPsk,
    wolfsslVerifyDefault,
    wolfsslSessCacheOff,
    wolfsslSessCacheClient,
    wolfsslSessCacheServer,
    wolfsslSessCacheBoth,
    wolfsslSessCacheNoAutoClear,
    wolfsslSessCacheNoInternalLookup,
    wolfsslSessCacheNoInternalStore,
    wolfsslSessCacheNoInternal,
    wolfsslErrorWantRead,
    wolfsslErrorWantWrite,
    wolfsslErrorWantConnect,
    wolfsslErrorWantAccept,
    wolfsslErrorSyscall,
    wolfsslErrorWantX509Lookup,
    wolfsslErrorZeroReturn,
    wolfsslErrorSsl,
    wolfsslSentShutdown,
    wolfsslReceivedShutdown,
    wolfsslModeAcceptMovingWriteBuffer,
    wolfsslRsslHandshakeFailure,
    wolfsslRtlsv1AlertUnknownCa,
    wolfsslRsslv3AlertCertificateUnknown,
    wolfsslRsslv3AlertBadCertificate,
};

// Based on Ada Binding
pub fn get_wolfssl_error_want_read() c_int {
    return c.WOLFSSL_ERROR_WANT_READ;
}
pub fn get_wolfssl_error_want_write() c_int {
    return c.WOLFSSL_ERROR_WANT_WRITE;
}
pub fn get_wolfssl_max_error_size() c_int {
    return c.WOLFSSL_MAX_ERROR_SZ;
}
pub fn get_wolfssl_success() c_int {
    return c.WOLFSSL_SUCCESS;
}
pub fn get_wolfssl_failure() c_int {
    return c.WOLFSSL_FAILURE;
}
pub fn get_wolfssl_verify_none() c_int {
    return c.WOLFSSL_VERIFY_NONE;
}
pub fn get_wolfssl_verify_peer() c_int {
    return c.WOLFSSL_VERIFY_PEER;
}
pub fn get_wolfssl_verify_fail_if_no_peer_cert() c_int {
    return c.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
}
pub fn get_wolfssl_verify_client_once() c_int {
    return c.WOLFSSL_VERIFY_CLIENT_ONCE;
}
pub fn get_wolfssl_verify_post_handshake() c_int {
    return c.WOLFSSL_VERIFY_POST_HANDSHAKE;
}
pub fn get_wolfssl_verify_fail_except_psk() c_int {
    return c.WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
}
pub fn get_wolfssl_verify_default() c_int {
    return c.WOLFSSL_VERIFY_DEFAULT;
}
pub fn get_wolfssl_filetype_asn1() c_int {
    return c.WOLFSSL_FILETYPE_ASN1;
}
pub fn get_wolfssl_filetype_pem() c_int {
    return c.WOLFSSL_FILETYPE_PEM;
}
pub fn get_wolfssl_filetype_default() c_int {
    return c.WOLFSSL_FILETYPE_DEFAULT;
}

pub fn get_wolfssl_error(self: *WolfSSL, ret: c_int) !void {
    try checkError(c.wolfSSL_get_error(self.ssl, ret));
}

test "Read cImport" {
    _ = c;
}

test "Init Client TLS" {
    var client = try init(.TLSv1_2Client);
    defer client.deinit() catch {};
}
