pub const c = @import("wolfssl_c");
const std = @import("std");
pub const crypto = std.crypto;
pub const tls = std.crypto.tls;

const WolfSSL = @This();

// fields
ctx: ?*c.WOLFSSL_CTX,
ssl: ?*c.WOLFSSL,

pub const tlsMethod = enum {
    TLSv1_2Client,
    TLSv1_2Server,
    TLSv1_1Client,
    TLSv1_1Server,
    TLSv1_3Client,
    TLSv1_3Server,
};

pub fn init(method: tlsMethod) !WolfSSL {
    try checkError(c.wolfSSL_Init());
    const tls_method = switch (method) {
        .TLSv1_1Client => c.wolfTLSv1_1_client_method(),
        .TLSv1_2Client => c.wolfTLSv1_2_client_method(),
        .TLSv1_3Client => c.wolfTLSv1_3_client_method(),
        .TLSv1_1Server => c.wolfTLSv1_1_server_method(),
        .TLSv1_2Server => c.wolfTLSv1_2_server_method(),
        .TLSv1_3Server => c.wolfTLSv1_3_server_method(),
    };
    var wolf: WolfSSL = undefined;
    wolf.ctx = c.wolfSSL_CTX_new(tls_method);
    wolf.ssl = c.wolfSSL_new(wolf.ctx);
    return wolf;
}

pub fn connect(self: *WolfSSL) !void {
    try checkError(c.wolfSSL_connect(self.ssl));
}

pub fn accept(self: *WolfSSL) !void {
    try checkError(c.wolfSSL_accept(self.ssl));
}

pub fn write(self: *WolfSSL, buffer: []const u8) !usize {
    const result = c.wolfSSL_write(self.ssl, buffer.ptr, @intCast(buffer.len));
    if (result <= 0) {
        try get_wolfssl_error(self, result);
        return error.WriteError;
    }
    return @intCast(result);
}

pub fn read(self: *WolfSSL, buffer: []u8) !usize {
    const result = c.wolfSSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
    if (result <= 0) {
        try get_wolfssl_error(self, result);
        return error.ReadError;
    }
    return @intCast(result);
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
        c.WOLFSSL_ALPN_NOT_FOUND => error.wolfsslAlpnNotFound,
        c.WOLFSSL_BAD_CERTTYPE => error.wolfsslBadCerttype,
        c.WOLFSSL_BAD_STAT => error.wolfsslBadStat,
        c.WOLFSSL_BAD_PATH => error.wolfsslBadPath,
        c.WOLFSSL_BAD_FILETYPE => error.wolfsslBadFiletype,
        c.WOLFSSL_BAD_FILE => error.wolfsslBadFile,
        c.WOLFSSL_NOT_IMPLEMENTED => error.wolfsslNotImplemented,
        c.WOLFSSL_UNKNOWN => error.wolfsslUnknown,
        c.WOLFSSL_FATAL_ERROR => error.wolfsslFatalError,

        c.WOLFSSL_ERROR_SYSCALL => error.wolfsslErrorSyscall,
        c.WOLFSSL_ERROR_WANT_X509_LOOKUP => error.wolfsslErrorWantX509Lookup,
        c.WOLFSSL_ERROR_ZERO_RETURN => error.wolfsslErrorZeroReturn,
        // c.WOLFSSL_ERROR_SSL => error.wolfsslErrorSsl,

        c.WOLFSSL_R_SSL_HANDSHAKE_FAILURE => error.wolfsslRsslHandshakeFailure,
        c.WOLFSSL_R_TLSV1_ALERT_UNKNOWN_CA => error.wolfsslRtlsv1AlertUnknownCa,
        c.WOLFSSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN => error.wolfsslRsslv3AlertCertificateUnknown,
        c.WOLFSSL_R_SSLV3_ALERT_BAD_CERTIFICATE => error.wolfsslRsslv3AlertBadCertificate,
        c.WOLFSSL_SUCCESS => {},
        else => {},
    };
}

const WolfSSLError = error{
    wolfsslFailure,
    wolfsslAlpnNotFound,
    wolfsslBadCerttype,
    wolfsslBadStat,
    wolfsslBadPath,
    wolfsslBadFiletype,
    wolfsslBadFile,
    wolfsslNotImplemented,
    wolfsslUnknown,
    wolfsslFatalError,

    wolfsslErrorSyscall,
    wolfsslErrorWantX509Lookup,
    wolfsslErrorZeroReturn,
    wolfsslErrorSsl,

    wolfsslModeAcceptMovingWriteBuffer,
    wolfsslRsslHandshakeFailure,
    wolfsslRtlsv1AlertUnknownCa,
    wolfsslRsslv3AlertCertificateUnknown,
    wolfsslRsslv3AlertBadCertificate,
    WriteError,
    ReadError,
};
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

const testing = std.testing;

test "Reference all declarations" {
    testing.refAllDecls(@This());
}

test "Init Client TLS" {
    {
        var client = try init(.TLSv1_1Client);
        defer client.deinit() catch |err| std.log.err("Failed to deinit client: {}", .{err});
    }
    {
        var client = try init(.TLSv1_2Client);
        defer client.deinit() catch |err| std.log.err("Failed to deinit client: {}", .{err});
    }
    {
        var client = try init(.TLSv1_3Client);
        defer client.deinit() catch |err| std.log.err("Failed to deinit client: {}", .{err});
    }
}

test "Init Server TLS" {
    {
        var server = try init(.TLSv1_1Server);
        defer server.deinit() catch |err| std.log.err("Failed to deinit server: {}", .{err});
    }
    {
        var server = try init(.TLSv1_2Server);
        defer server.deinit() catch |err| std.log.err("Failed to deinit server: {}", .{err});
    }
    {
        var server = try init(.TLSv1_3Server);
        defer server.deinit() catch |err| std.log.err("Failed to deinit server: {}", .{err});
    }
}

test "WolfSSL Verify Modes" {
    try testing.expectEqual(get_wolfssl_verify_none(), c.WOLFSSL_VERIFY_NONE);
    try testing.expectEqual(get_wolfssl_verify_peer(), c.WOLFSSL_VERIFY_PEER);
    try testing.expectEqual(get_wolfssl_verify_default(), c.WOLFSSL_VERIFY_DEFAULT);
}

test "WolfSSL File Types" {
    try testing.expectEqual(get_wolfssl_filetype_asn1(), c.WOLFSSL_FILETYPE_ASN1);
    try testing.expectEqual(get_wolfssl_filetype_pem(), c.WOLFSSL_FILETYPE_PEM);
    try testing.expectEqual(get_wolfssl_filetype_default(), c.WOLFSSL_FILETYPE_DEFAULT);
}
