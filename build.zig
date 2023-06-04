const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Options
    const shared = b.option(bool, "Shared", "Build the Shared Library [default: false]") orelse false;

    const lib = if (shared) b.addSharedLibrary(.{
        .name = "wolfssl",
        .target = target,
        .optimize = optimize,
        .version = .{
            .major = 5,
            .minor = 6,
            .patch = 0,
        },
    }) else b.addStaticLibrary(.{
        .name = "wolfssl",
        .target = target,
        .optimize = optimize,
    });

    switch (optimize) {
        .Debug, .ReleaseSafe => lib.bundle_compiler_rt = true,
        else => lib.strip = true,
    }
    lib.addIncludePath("wolfssl");
    lib.addIncludePath(sdkPath("/"));
    lib.addCSourceFiles(&wolfssl_sources, &cflags);
    lib.addCSourceFiles(&wolfcrypt_sources, &cflags);
    lib.defineCMacro("TFM_TIMING_RESISTANT", null);
    lib.defineCMacro("ECC_TIMING_RESISTANT", null);
    lib.defineCMacro("WC_RSA_BLINDING", null);
    lib.defineCMacro("HAVE_PTHREAD", null);
    lib.defineCMacro("NO_INLINE", null);
    lib.defineCMacro("WOLFSSL_TLS13", null);
    lib.defineCMacro("WC_RSA_PSS", null);
    lib.defineCMacro("HAVE_TLS_EXTENSIONS", null);
    lib.defineCMacro("HAVE_SNI", null);
    lib.defineCMacro("HAVE_MAX_FRAGMENT", null);
    lib.defineCMacro("HAVE_TRUNCATED_HMAC", null);
    lib.defineCMacro("HAVE_ALPN", null);
    lib.defineCMacro("HAVE_TRUSTED_CA", null);
    lib.defineCMacro("HAVE_HKDF", null);
    lib.defineCMacro("BUILD_GCM", null);
    lib.defineCMacro("HAVE_AESCCM", null);
    lib.defineCMacro("HAVE_SESSION_TICKET", null);
    lib.defineCMacro("HAVE_CHACHA", null);
    lib.defineCMacro("HAVE_POLY1305", null);
    lib.defineCMacro("HAVE_ECC", null);
    lib.defineCMacro("HAVE_FFDHE_2048", null);
    lib.defineCMacro("HAVE_FFDHE_3072", null);
    lib.defineCMacro("HAVE_FFDHE_4096", null);
    lib.defineCMacro("HAVE_FFDHE_6144", null);
    lib.defineCMacro("HAVE_FFDHE_8192", null);
    lib.defineCMacro("HAVE_ONE_TIME_AUTH", null);
    lib.defineCMacro("HAVE_SYS_TIME_H", null);
    lib.defineCMacro("SESSION_INDEX", null);
    lib.defineCMacro("SESSION_CERTS", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509", null);
    lib.defineCMacro("OPENSSL_EXTRA_X509_SMALL", null);
    lib.linkLibC();

    lib.installHeadersDirectory("wolfssl", "");

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);
}

const cflags = [_][]const u8{
    "-std=gnu89",
    "-Wall",
};

const wolfssl_sources = [_][]const u8{
    sdkPath("/src/bio.c"),
    sdkPath("/src/conf.c"),
    sdkPath("/src/crl.c"),
    sdkPath("/src/dtls.c"),
    sdkPath("/src/dtls13.c"),
    sdkPath("/src/internal.c"),
    sdkPath("/src/keys.c"),
    sdkPath("/src/ocsp.c"),
    sdkPath("/src/pk.c"),
    sdkPath("/src/quic.c"),
    sdkPath("/src/sniffer.c"),
    sdkPath("/src/ssl.c"),
    sdkPath("/src/ssl_asn1.c"),
    sdkPath("/src/ssl_bn.c"),
    sdkPath("/src/ssl_misc.c"),
    sdkPath("/src/tls.c"),
    sdkPath("/src/tls13.c"),
    sdkPath("/src/wolfio.c"),
    sdkPath("/src/x509.c"),
    sdkPath("/src/x509_str.c"),
};

const wolfcrypt_sources = [_][]const u8{
    sdkPath("/wolfcrypt/src/aes.c"),
    sdkPath("/wolfcrypt/src/arc4.c"),
    sdkPath("/wolfcrypt/src/asm.c"),
    sdkPath("/wolfcrypt/src/asn.c"),
    sdkPath("/wolfcrypt/src/blake2b.c"),
    sdkPath("/wolfcrypt/src/blake2s.c"),
    sdkPath("/wolfcrypt/src/camellia.c"),
    sdkPath("/wolfcrypt/src/chacha.c"),
    sdkPath("/wolfcrypt/src/chacha20_poly1305.c"),
    sdkPath("/wolfcrypt/src/cmac.c"),
    sdkPath("/wolfcrypt/src/coding.c"),
    sdkPath("/wolfcrypt/src/compress.c"),
    sdkPath("/wolfcrypt/src/cpuid.c"),
    sdkPath("/wolfcrypt/src/cryptocb.c"),
    sdkPath("/wolfcrypt/src/curve25519.c"),
    sdkPath("/wolfcrypt/src/curve448.c"),
    sdkPath("/wolfcrypt/src/des3.c"),
    sdkPath("/wolfcrypt/src/dh.c"),
    sdkPath("/wolfcrypt/src/dilithium.c"),
    sdkPath("/wolfcrypt/src/dsa.c"),
    sdkPath("/wolfcrypt/src/ecc.c"),
    sdkPath("/wolfcrypt/src/ecc_fp.c"),
    sdkPath("/wolfcrypt/src/eccsi.c"),
    sdkPath("/wolfcrypt/src/ed25519.c"),
    sdkPath("/wolfcrypt/src/ed448.c"),
    sdkPath("/wolfcrypt/src/error.c"),
    sdkPath("/wolfcrypt/src/evp.c"),
    sdkPath("/wolfcrypt/src/ext_kyber.c"),
    sdkPath("/wolfcrypt/src/falcon.c"),
    sdkPath("/wolfcrypt/src/fe_448.c"),
    sdkPath("/wolfcrypt/src/fe_low_mem.c"),
    sdkPath("/wolfcrypt/src/fe_operations.c"),
    sdkPath("/wolfcrypt/src/ge_448.c"),
    sdkPath("/wolfcrypt/src/ge_low_mem.c"),
    sdkPath("/wolfcrypt/src/ge_operations.c"),
    sdkPath("/wolfcrypt/src/hash.c"),
    sdkPath("/wolfcrypt/src/hmac.c"),
    sdkPath("/wolfcrypt/src/hpke.c"),
    sdkPath("/wolfcrypt/src/integer.c"),
    sdkPath("/wolfcrypt/src/kdf.c"),
    sdkPath("/wolfcrypt/src/logging.c"),
    sdkPath("/wolfcrypt/src/md2.c"),
    sdkPath("/wolfcrypt/src/md4.c"),
    sdkPath("/wolfcrypt/src/md5.c"),
    sdkPath("/wolfcrypt/src/memory.c"),
    sdkPath("/wolfcrypt/src/misc.c"),
    sdkPath("/wolfcrypt/src/pkcs12.c"),
    sdkPath("/wolfcrypt/src/pkcs7.c"),
    sdkPath("/wolfcrypt/src/poly1305.c"),
    sdkPath("/wolfcrypt/src/pwdbased.c"),
    sdkPath("/wolfcrypt/src/random.c"),
    sdkPath("/wolfcrypt/src/rc2.c"),
    sdkPath("/wolfcrypt/src/ripemd.c"),
    sdkPath("/wolfcrypt/src/rsa.c"),
    sdkPath("/wolfcrypt/src/sakke.c"),
    sdkPath("/wolfcrypt/src/sha.c"),
    sdkPath("/wolfcrypt/src/sha256.c"),
    sdkPath("/wolfcrypt/src/sha3.c"),
    sdkPath("/wolfcrypt/src/sha512.c"),
    sdkPath("/wolfcrypt/src/signature.c"),
    sdkPath("/wolfcrypt/src/siphash.c"),
    sdkPath("/wolfcrypt/src/sp_arm32.c"),
    sdkPath("/wolfcrypt/src/sp_arm64.c"),
    sdkPath("/wolfcrypt/src/sp_armthumb.c"),
    sdkPath("/wolfcrypt/src/sp_c32.c"),
    sdkPath("/wolfcrypt/src/sp_c64.c"),
    sdkPath("/wolfcrypt/src/sp_cortexm.c"),
    sdkPath("/wolfcrypt/src/sp_dsp32.c"),
    sdkPath("/wolfcrypt/src/sp_int.c"),
    sdkPath("/wolfcrypt/src/sp_x86_64.c"),
    sdkPath("/wolfcrypt/src/sphincs.c"),
    sdkPath("/wolfcrypt/src/srp.c"),
    sdkPath("/wolfcrypt/src/tfm.c"),
    sdkPath("/wolfcrypt/src/wc_dsp.c"),
    sdkPath("/wolfcrypt/src/wc_encrypt.c"),
    sdkPath("/wolfcrypt/src/wc_kyber.c"),
    sdkPath("/wolfcrypt/src/wc_kyber_poly.c"),
    sdkPath("/wolfcrypt/src/wc_pkcs11.c"),
    sdkPath("/wolfcrypt/src/wc_port.c"),
    sdkPath("/wolfcrypt/src/wolfevent.c"),
    sdkPath("/wolfcrypt/src/wolfmath.c"),
};

fn sdkPath(comptime suffix: []const u8) []const u8 {
    if (suffix[0] != '/') @compileError("relToPath requires an absolute path!");
    return comptime blk: {
        @setEvalBranchQuota(2000);
        const root_dir = std.fs.path.dirname(@src().file) orelse ".";
        break :blk root_dir ++ suffix;
    };
}
