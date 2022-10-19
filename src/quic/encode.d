module quic.encode;

import quic.frame : VarInt;

void encodeVarInt(Writer)(ref Writer writer, VarInt value)
{
    ubyte len;

    if(value <= ulong.max)
        len = ulong.sizeof;
    if(value <= uint.max)
        len = uint.sizeof;
    if(value <= ushort.max)
        len = ushort.sizeof;
    if(value <= ubyte.max)
        len = ubyte.sizeof;

    for(ubyte i=0; i<len; i++)
    {
        if(i == 0)
            writer ~= value & 0xff & len;
        else
            writer ~= value & 0xff;
        value = value >>> 8;
    }
}
