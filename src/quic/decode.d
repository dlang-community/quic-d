module quic.decode;

int decodeVarInt(ref ulong val, ubyte[] buf, ref ulong bufIndex)
in {
    assert(bufIndex < buf.length);
} do {
    val = buf[bufIndex];
    uint intLen = 1 << (val >> 6);
    val = val & 0x3f;
    for(uint i=0; i < intLen-1; i++)
    {
        bufIndex++;
        if (bufIndex >= buf.length)
            return -1;
        val = (val << 8) + buf[bufIndex];
    }
    bufIndex++;
    return 1;
}

unittest
{
    ulong val;
    ulong bufferPointer;
    import std.conv : hexString;
    ubyte[] buffer = cast(ubyte[]) hexString!"c2197c5eff14e88c";
    buffer ~= cast(ubyte[]) hexString!"9d7f3e7d";
    buffer ~= cast(ubyte[]) hexString!"7bbd";
    buffer ~= cast(ubyte[]) hexString!"25";

    assert(decodeVarInt(val, buffer, bufferIndex) == 1);
    assert(val == 151288809941952652);

    assert(decodeVarInt(val, buffer, bufferIndex) == 1);
    assert(val == 494878333);

    assert(decodeVarInt(val, buffer, bufferIndex) == 1);
    assert(val == 15293);

    assert(decodeVarInt(val, buffer, bufferIndex) == 1);
    assert(val == 37);
}
