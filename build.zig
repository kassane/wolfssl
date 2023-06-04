const std = @import("std");
const Path = std.Build.LazyPath;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("wolfssl", .{ .root_source_file = b.path("wrapper/Zig/binding.zig") });

    // Options
    const shared = b.option(bool, "Shared", "Build the Shared Library [default: false]") orelse false;
    const tests = b.option(bool, "Tests", "Build all tests [default: true]") orelse false;

    // {} void == define, null == undef
    const config = b.addConfigHeader(.{
        .style = .blank,
        .include_path = "wolfssl/options.h",
    }, .{
        .ECC_SHAMIR = {},
        .ECC_TIMING_RESISTANT = {},
        .GCM_TABLE_4BIT = {},
        .HAVE_AESGCM = {},
        .HAVE_CHACHA = {},
        .HAVE_DH_DEFAULT_PARAMS = {},
        .HAVE_ECC = {},
        .HAVE_ENCRYPT_THEN_MAC = {},
        .HAVE_EXTENDED_MASTER = {},
        .HAVE_FFDHE_2048 = {},
        .HAVE_HASHDRBG = {},
        .HAVE_HKDF = {},
        .HAVE_POLY1305 = {},
        .HAVE_PTHREAD = if (target.result.abi != .msvc) {} else null,
        .HAVE_SUPPORTED_CURVES = {},
        .HAVE_THREAD_LS = {},
        .HAVE_TLS_EXTENSIONS = {},
        .HAVE_ONE_TIME_AUTH = {},
        .NO_DES3 = {},
        .NO_DSA = {},
        .NO_MD4 = {},
        .NO_PSK = {},
        .WOLFSSL_BASE64_ENCODE = {},
        .WOLFSSL_PSS_LONG_SALT = {},
        .WOLFSSL_SHA224 = {},
        .WOLFSSL_SHA384 = {},
        .WOLFSSL_SHA3 = null,
        .WOLFSSL_SHA512 = {},
        .WOLFSSL_SYS_CA_CERTS = {},
        .WOLFSSL_TLS13 = {},
        .WOLFSSL_USE_ALIGN = {},
        .WOLFSSL_X86_64_BUILD = if (isX86(target)) {} else null,
        .WC_NO_ASYNC_THREADING = {},
        .WC_RSA_BLINDING = {},
        .WC_RSA_PSS = {},
        .TFM_ECC256 = {},
        .TFM_TIMING_RESISTANT = {},
    });

    const lib = if (shared) b.addSharedLibrary(.{
        .name = "wolfssl",
        .target = target,
        .optimize = optimize,
        .version = .{
            .major = 5,
            .minor = 8,
            .patch = 0,
        },
    }) else b.addStaticLibrary(.{
        .name = "wolfssl",
        .target = target,
        .optimize = optimize,
    });

    switch (optimize) {
        .Debug, .ReleaseSafe => lib.bundle_compiler_rt = true,
        else => lib.root_module.strip = true,
    }
    lib.addConfigHeader(config);
    lib.root_module.addIncludePath(b.path(config.include_path));
    lib.root_module.addIncludePath(b.path("wolfssl"));
    lib.root_module.addIncludePath(b.path("."));
    lib.root_module.addCSourceFiles(.{ .files = wolfssl_sources, .flags = cflags });
    lib.root_module.addCSourceFiles(.{ .files = wolfcrypt_sources, .flags = cflags });
    lib.root_module.addCMacro("TFM_TIMING_RESISTANT", "");
    lib.root_module.addCMacro("ECC_TIMING_RESISTANT", "");
    lib.root_module.addCMacro("WC_RSA_BLINDING", "");
    lib.root_module.addCMacro("NO_INLINE", "");
    lib.root_module.addCMacro("WOLFSSL_TLS13", "");
    lib.root_module.addCMacro("WC_RSA_PSS", "");
    lib.root_module.addCMacro("HAVE_TLS_EXTENSIONS", "");
    lib.root_module.addCMacro("HAVE_SNI", "");
    lib.root_module.addCMacro("HAVE_MAX_FRAGMENT", "");
    lib.root_module.addCMacro("HAVE_TRUNCATED_HMAC", "");
    lib.root_module.addCMacro("HAVE_ALPN", "");
    lib.root_module.addCMacro("HAVE_TRUSTED_CA", "");
    lib.root_module.addCMacro("HAVE_HKDF", "");
    lib.root_module.addCMacro("BUILD_GCM", "");
    lib.root_module.addCMacro("HAVE_AESCCM", "");
    lib.root_module.addCMacro("HAVE_SESSION_TICKET", "");
    lib.root_module.addCMacro("HAVE_CHACHA", "");
    lib.root_module.addCMacro("HAVE_POLY1305", "");
    lib.root_module.addCMacro("HAVE_ECC", "");
    lib.root_module.addCMacro("HAVE_FFDHE_2048", "");
    lib.root_module.addCMacro("HAVE_FFDHE_3072", "");
    lib.root_module.addCMacro("HAVE_FFDHE_4096", "");
    lib.root_module.addCMacro("HAVE_FFDHE_6144", "");
    lib.root_module.addCMacro("HAVE_FFDHE_8192", "");
    lib.root_module.addCMacro("HAVE_ONE_TIME_AUTH", "");
    lib.root_module.addCMacro("SESSION_INDEX", "");
    lib.root_module.addCMacro("SESSION_CERTS", "");
    lib.root_module.addCMacro("OPENSSL_EXTRA_X509", "");
    lib.root_module.addCMacro("OPENSSL_EXTRA_X509_SMALL", "");
    if (lib.rootModuleTarget().abi == .msvc) {
        lib.root_module.addCMacro("SINGLE_THREADED", "");
        lib.linkSystemLibrary("advapi32");
    } else {
        lib.root_module.addCMacro("HAVE_SYS_TIME_H", "");
        lib.root_module.addCMacro("HAVE_PTHREAD", "");
    }
    if (lib.rootModuleTarget().isMinGW()) {
        lib.root_module.linkSystemLibrary("pthread", .{});
    }
    lib.linkLibC();

    lib.installHeadersDirectory(b.path("wolfssl"), "", .{});

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    if (tests) {
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/asn1/asn1.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/echoclient/echoclient.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/echoserver/echoserver.c",
        });
        // Errors
        // buildExe(b, .{
        //     .target = target,
        //     .optimize = optimize,
        //     .lib = lib,
        //     .path = "examples/client/client.c",
        // });
        // buildExe(b, .{
        //     .target = target,
        //     .optimize = optimize,
        //     .lib = lib,
        //     .path = "examples/server/server.c",
        // });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/sctp/sctp-client.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/sctp/sctp-server.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/sctp/sctp-client-dtls.c",
        });
        buildExe(b, .{
            .target = target,
            .optimize = optimize,
            .lib = lib,
            .path = "examples/sctp/sctp-server-dtls.c",
        });
    }
}

fn buildExe(b: *std.Build, info: BuildInfo) void {
    const exe = b.addExecutable(.{
        .name = info.filename(),
        .target = info.target,
        .optimize = info.optimize,
    });
    exe.addCSourceFile(.{ .file = b.path(info.path), .flags = cflags });
    // get library include headers
    for (info.lib.root_module.include_dirs.items) |include| {
        exe.root_module.include_dirs.append(b.allocator, include) catch {};
    }
    if (exe.rootModuleTarget().os.tag == .windows) {
        exe.want_lto = false;
        exe.linkSystemLibrary("ws2_32");
        exe.linkSystemLibrary("crypt32");
    }
    exe.linkLibrary(info.lib);
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step(info.filename(), b.fmt("Run the {s} sample", .{info.filename()}));
    run_step.dependOn(&run_cmd.step);
}

const cflags = &.{
    "-std=gnu89",
    "-Wno-pragmas",
    "-Wall",
    "-Wextra",
    "-Wunknown-pragmas",
    "--param=ssp-buffer-size=1",
    "-Waddress",
    "-Warray-bounds",
    "-Wbad-function-cast",
    "-Wchar-subscripts",
    "-Wcomment",
    "-Wfloat-equal",
    "-Wformat-security",
    "-Wformat=2",
    "-Wmaybe-uninitialized",
    "-Wmissing-field-initializers",
    "-Wmissing-noreturn",
    "-Wmissing-prototypes",
    "-Wnested-externs",
    "-Wnormalized=id",
    "-Woverride-init",
    "-Wpointer-arith",
    "-Wpointer-sign",
    "-Wshadow",
    "-Wsign-compare",
    "-Wstrict-overflow=1",
    "-Wstrict-prototypes",
    "-Wswitch-enum",
    "-Wundef",
    "-Wunused",
    "-Wunused-result",
    "-Wunused-variable",
    "-Wwrite-strings",
    "-fwrapv",
};

const wolfssl_sources = &.{
    "src/bio.c",
    "src/conf.c",
    "src/crl.c",
    "src/dtls.c",
    "src/dtls13.c",
    "src/internal.c",
    "src/keys.c",
    "src/ocsp.c",
    "src/pk.c",
    "src/quic.c",
    "src/sniffer.c",
    "src/ssl.c",
    "src/ssl_asn1.c",
    "src/ssl_bn.c",
    "src/ssl_misc.c",
    "src/tls.c",
    "src/tls13.c",
    "src/wolfio.c",
    "src/x509.c",
    "src/x509_str.c",
};

const wolfcrypt_sources = &.{
    "wolfcrypt/src/aes.c",
    "wolfcrypt/src/arc4.c",
    "wolfcrypt/src/asm.c",
    "wolfcrypt/src/asn.c",
    "wolfcrypt/src/blake2b.c",
    "wolfcrypt/src/blake2s.c",
    "wolfcrypt/src/camellia.c",
    "wolfcrypt/src/chacha.c",
    "wolfcrypt/src/chacha20_poly1305.c",
    "wolfcrypt/src/cmac.c",
    "wolfcrypt/src/coding.c",
    "wolfcrypt/src/compress.c",
    "wolfcrypt/src/cpuid.c",
    "wolfcrypt/src/cryptocb.c",
    "wolfcrypt/src/curve25519.c",
    "wolfcrypt/src/curve448.c",
    "wolfcrypt/src/des3.c",
    "wolfcrypt/src/dh.c",
    "wolfcrypt/src/dilithium.c",
    "wolfcrypt/src/dsa.c",
    "wolfcrypt/src/ecc.c",
    "wolfcrypt/src/ecc_fp.c",
    "wolfcrypt/src/eccsi.c",
    "wolfcrypt/src/ed25519.c",
    "wolfcrypt/src/ed448.c",
    "wolfcrypt/src/error.c",
    "wolfcrypt/src/evp.c",
    "wolfcrypt/src/ext_kyber.c",
    "wolfcrypt/src/falcon.c",
    "wolfcrypt/src/fe_448.c",
    "wolfcrypt/src/fe_low_mem.c",
    "wolfcrypt/src/fe_operations.c",
    "wolfcrypt/src/ge_448.c",
    "wolfcrypt/src/ge_low_mem.c",
    "wolfcrypt/src/ge_operations.c",
    "wolfcrypt/src/hash.c",
    "wolfcrypt/src/hmac.c",
    "wolfcrypt/src/hpke.c",
    "wolfcrypt/src/integer.c",
    "wolfcrypt/src/kdf.c",
    "wolfcrypt/src/logging.c",
    "wolfcrypt/src/md2.c",
    "wolfcrypt/src/md4.c",
    "wolfcrypt/src/md5.c",
    "wolfcrypt/src/memory.c",
    "wolfcrypt/src/misc.c",
    "wolfcrypt/src/pkcs12.c",
    "wolfcrypt/src/pkcs7.c",
    "wolfcrypt/src/poly1305.c",
    "wolfcrypt/src/pwdbased.c",
    "wolfcrypt/src/random.c",
    "wolfcrypt/src/rc2.c",
    "wolfcrypt/src/ripemd.c",
    "wolfcrypt/src/rsa.c",
    "wolfcrypt/src/sakke.c",
    "wolfcrypt/src/sha.c",
    "wolfcrypt/src/sha256.c",
    "wolfcrypt/src/sha3.c",
    "wolfcrypt/src/sha512.c",
    "wolfcrypt/src/signature.c",
    "wolfcrypt/src/siphash.c",
    "wolfcrypt/src/sp_arm32.c",
    "wolfcrypt/src/sp_arm64.c",
    "wolfcrypt/src/sp_armthumb.c",
    "wolfcrypt/src/sp_c32.c",
    "wolfcrypt/src/sp_c64.c",
    "wolfcrypt/src/sp_cortexm.c",
    "wolfcrypt/src/sp_dsp32.c",
    "wolfcrypt/src/sp_int.c",
    "wolfcrypt/src/sp_x86_64.c",
    "wolfcrypt/src/sphincs.c",
    "wolfcrypt/src/srp.c",
    "wolfcrypt/src/tfm.c",
    "wolfcrypt/src/wc_dsp.c",
    "wolfcrypt/src/wc_encrypt.c",
    "wolfcrypt/src/wc_kyber.c",
    "wolfcrypt/src/wc_kyber_poly.c",
    "wolfcrypt/src/wc_pkcs11.c",
    "wolfcrypt/src/wc_port.c",
    "wolfcrypt/src/wolfevent.c",
    "wolfcrypt/src/wolfmath.c",
};

fn isX86(target: std.Build.ResolvedTarget) bool {
    return switch (target.result.cpu.arch) {
        .x86, .x86_64 => true,
        else => false,
    };
}

const BuildInfo = struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    path: []const u8,
    lib: *std.Build.Step.Compile,

    fn filename(self: BuildInfo) []const u8 {
        var split = std.mem.splitSequence(u8, std.fs.path.basename(self.path), ".");
        return split.first();
    }
};
