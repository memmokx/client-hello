const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Extension = struct {
    id: u16 = 0,
    data: []u8 = &.{},
};

pub const ClientHello = struct {
    version: u16 = 0,
    client_random: []u8 = &.{},
    session_id: []u8 = &.{},
    cipher_suites: []u16 = &.{},
    compression_methods: []u8 = &.{},
    extensions: []Extension = &.{},
};

pub fn unmarshalClientHello(allocator: Allocator, bytes: []const u8) !ClientHello {
    var stream = std.io.fixedBufferStream(bytes);
    var couting_reader = std.io.countingReader(stream.reader());
    var reader = couting_reader.reader();
    var client_hello = ClientHello{};

    const handshake_type: u8 = try reader.readByte();
    if (handshake_type != 1) return error.InvalidHandshakeType;

    const handshake_length: u32 = try reader.readVarInt(u32, .Big, 3);
    var limited_reader = std.io.limitedReader(reader, @intCast(handshake_length));
    var handshake_reader = limited_reader.reader();

    try unmarshalHelloHeader(allocator, handshake_reader, &client_hello);
    errdefer allocator.free(client_hello.client_random);
    errdefer allocator.free(client_hello.session_id);

    try unmarshalCipherSuites(allocator, handshake_reader, &client_hello);
    errdefer allocator.free(client_hello.cipher_suites);

    try unmarshalCompressionMethods(allocator, handshake_reader, &client_hello);
    errdefer allocator.free(client_hello.compression_methods);

    try unmarshalExtensions(allocator, handshake_reader, &client_hello);

    return client_hello;
}

fn unmarshalHelloHeader(allocator: Allocator, reader: anytype, hello: *ClientHello) !void {
    hello.version = try reader.readInt(u16, .Big);
    hello.client_random = try allocator.alloc(u8, 32);
    errdefer allocator.free(hello.client_random);

    assert(try reader.readAll(hello.client_random) == 32);

    const session_id_len: usize = @intCast(try reader.readByte());
    hello.session_id = try allocator.alloc(u8, session_id_len);
    errdefer allocator.free(hello.session_id);

    assert(try reader.readAll(hello.session_id) == session_id_len);
}

fn unmarshalCipherSuites(allocator: Allocator, reader: anytype, hello: *ClientHello) !void {
    const cipher_suites_len: usize = try reader.readVarInt(usize, .Big, 2);
    var limited_reader = std.io.limitedReader(reader, @intCast(cipher_suites_len));

    hello.cipher_suites = try allocator.alloc(u16, cipher_suites_len / 2);
    errdefer allocator.free(hello.cipher_suites);

    for (hello.cipher_suites) |*cipher_suite| {
        cipher_suite.* = try limited_reader.reader().readInt(u16, .Big);
    }
}

fn unmarshalCompressionMethods(allocator: Allocator, reader: anytype, hello: *ClientHello) !void {
    const methods_len: usize = try reader.readVarInt(usize, .Big, 1);
    var limited_reader = std.io.limitedReader(reader, @intCast(methods_len));

    hello.compression_methods = try allocator.alloc(u8, methods_len);
    errdefer allocator.free(hello.compression_methods);

    assert(try limited_reader.reader().readAll(hello.compression_methods) == methods_len);
}

fn unmarshalExtensions(allocator: Allocator, reader: anytype, hello: *ClientHello) !void {
    const extensions_len: usize = try reader.readVarInt(usize, .Big, 2);
    var limited_reader = std.io.limitedReader(reader, @intCast(extensions_len));

    var extensions = std.ArrayList(Extension).init(allocator);
    errdefer extensions.deinit();

    while (limited_reader.reader().readInt(u16, .Big)) |extension| {
        const extension_len: usize = try limited_reader.reader().readVarInt(usize, .Big, 2);
        const data = try allocator.alloc(u8, extension_len);
        errdefer allocator.free(data);

        assert(try limited_reader.reader().readAll(data) == extension_len);

        try extensions.append(Extension{
            .id = extension,
            .data = data,
        });
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => |e| return e,
    }

    hello.extensions = try extensions.toOwnedSlice();
}

fn isGrease(data: u16) bool {
    return (data & 0x0a0a) == 0x0a0a and ((data & 0xff00) >> 8) == (data & 0x00ff);
}

test "isGrease" {
    try std.testing.expect(isGrease(0x0a0a));
    try std.testing.expect(isGrease(0x1a1a));
    try std.testing.expect(isGrease(0x2a2a));
    try std.testing.expect(isGrease(0x3a3a));
    try std.testing.expect(isGrease(0x4a4a));
    try std.testing.expect(isGrease(0x5a5a));
    try std.testing.expect(isGrease(0x6a6a));
    try std.testing.expect(isGrease(0x7a7a));
    try std.testing.expect(isGrease(0x8a8a));
    try std.testing.expect(isGrease(0x9a9a));
    try std.testing.expect(isGrease(0xaaaa));
    try std.testing.expect(isGrease(0xbaba));
    try std.testing.expect(isGrease(0xcaca));
    try std.testing.expect(isGrease(0xdada));
    try std.testing.expect(isGrease(0xeaea));
    try std.testing.expect(isGrease(0xfafa));

    try std.testing.expect(!isGrease(0x1aba));
    try std.testing.expect(!isGrease(0x123));
    try std.testing.expect(!isGrease(0x0aca));
}
