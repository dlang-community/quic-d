module quic.encode;

import quic.frame : VarInt;

ubyte getVarIntBitMask(ubyte len)
{
    uint bitMask;
    while(len > 1)
    {
        bitMask++; 
        len = len >>> 1; 
    }
    return cast(ubyte)((bitMask << 6));
}

void encodeVarInt(Writer)(ref Writer writer, VarInt value)
in {
    assert(value < (1UL << 62), "Value is too big");
} do {
    ubyte len;
    if (value < 1UL << 6)
        len = 1;
    else if (value < 1UL << 14)
        len = 2;
    else if (value < 1UL << 30)
        len = 4;
    else if (value < 1UL << 62)
        len = 8;

    import std.bitmanip : nativeToBigEndian;
    auto bigEndianValue = nativeToBigEndian(value);

    foreach (i, elem; bigEndianValue[$-len..$])
    {
        if (i == 0)
            writer ~= elem | getVarIntBitMask(len);
        else
            writer ~= elem;
    }
}

unittest
{
    import std.conv : hexString;
    
	ubyte[] testBuf = cast(ubyte[]) hexString!"c2197c5eff14e88c";
    testBuf ~= cast(ubyte[]) hexString!"9d7f3e7d";
    testBuf ~= cast(ubyte[]) hexString!"7bbd";
    testBuf ~= cast(ubyte[]) hexString!"25";

	ubyte[] buf;
	encodeVarInt(buf, 151288809941952652);
	encodeVarInt(buf, 494878333);
	encodeVarInt(buf, 15293);
	encodeVarInt(buf, 37);

	assert(testBuf == buf);
}
