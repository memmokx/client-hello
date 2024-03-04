const std = @import("std");
const Allocator = std.mem.Allocator;
const tls = @import("client_hello.zig");
const ClientHello = tls.ClientHello;
const Extension = tls.Extension;

pub fn fromClientHello(allocator: Allocator, hello: ClientHello) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var writer = buffer.writer();

    try writer.print("{d},", .{hello.version});
    for (hello.cipher_suites, 0..) |cipher, i| {
        if (tls.isGrease(cipher))
            continue;
        try writer.print("{d}", .{cipher});
        if (i != hello.cipher_suites.len - 1)
            try writer.writeByte('-');
    }
    try writer.writeByte(',');

    for (hello.extensions, 0..) |extension, i| {
        if (tls.isGrease(extension.id))
            continue;
        try writer.print("{d}", .{extension.id});
        if (i != hello.extensions.len - 1)
            try writer.writeByte('-');
    }
    try writer.writeByte(',');

    if (try hello.getExtension(tls.SupportedGroupsExt, allocator)) |curves| {
        defer allocator.free(curves.supported_groups);
        std.debug.print("{any}\n", .{curves.supported_groups});
        for (curves.supported_groups, 0..) |curve, i| {
            if (tls.isGrease(curve))
                continue;
            try writer.print("{d}", .{curve});
            if (i != curves.supported_groups.len - 1)
                try writer.writeByte('-');
        }
    }
    try writer.writeByte(',');

    if (try hello.getExtension(tls.SupportedPointsFormatsExt, allocator)) |points| {
        defer allocator.free(points.supported_formats);

        for (points.supported_formats, 0..) |format, i| {
            if (tls.isGrease(format))
                continue;
            try writer.print("{d}", .{format});
            if (i != points.supported_formats.len - 1)
                try writer.writeByte('-');
        }
    }

    return buffer.toOwnedSliceSentinel(0);
}
