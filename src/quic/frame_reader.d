module quic.frame_reader;

import quic.frame;
import quic.packet;
import quic.attributes;

struct QuicFrameReader(FrameType)
{
    import quic.decode : decodeVarInt;

    ubyte[] networkStream;
    ulong bufIndex;

    this(ubyte[] networkStream, ulong bufIndex)
    {
        this.networkStream = networkStream; 
        this.bufIndex = bufIndex;
    }

    auto opDispatch(string name)() {
            alias FieldType = typeof(mixin(FrameType.stringof, '.', name));

            FieldType value;

            static if (is(FieldType == VarInt))
            {
                decodeVarInt(value, networkStream, bufIndex);
                return value;
            }

            else static if (is(FieldType == AckRange))
            {
                decodeVarInt(value.gap, networkStream, bufIndex);
                decodeVarInt(value.rangeLength, networkStream, bufIndex);
                return value;
            }

            else static if ((is(FieldType == EcnCount)))
            {
                decodeVarInt(value.ect0Count, networkStream, bufIndex);
                decodeVarInt(value.ect1Count, networkStream, bufIndex);
                decodeVarInt(value.ecn_ceCount, networkStream, bufIndex);
                return value;
            }

            else static if (is(FieldType == ubyte[]))
            {
                alias attributes = __traits(getAttributes, mixin(FrameType.stringof, '.', name)); 
                static if(is(attributes == VarIntLength))
                {
                    VarInt len;
                    decodeVarInt(len, networkStream, bufIndex);
                    bufIndex += len; 
                    return networkStream[bufIndex-len..bufIndex];
                }

                static if(hasFixedLengh!attributes[0])
                {
                    auto lenOfLength = getFixedLength!attributes[0];
                    auto len = decodeBigEndianField(networkStream, bufIndex, len);
                    bufIndex += len;
                    return networkStream[bufIndex-len..bufIndex];
                }
            }

            else static if(hasEstablishedLength!attributes[0])
            {
                    auto len = getEstablishedLength!attributes[0];
                    bufIndex += len;
                    return networkStream[bufIndex-len..bufIndex];
            }
        }
}

ulong decodeBigEndianField(FieldType)(ubyte[] networkStream, ref ulong bufIndex, uint len)
{
    int value;
    while(len)
    {
        fieldLen = (fieldLen << 8) + networkStream[bufIndex];
        bufIndex++;
        len--;
    }
    bufIndex += fieldLen;
    return value;
}

unittest
{
    import std.conv : hexString;

    ubyte[] networkStream = cast(ubyte[]) hexString!"c2197c5eff14e88c";
    networkStream ~= cast(ubyte[]) hexString!"9d7f3e7d";
    ulong bufIndex;
    auto reader = QuicFrameReader!AckFrame(networkStream, bufIndex);
    assert(reader.largestAcknowledged == 151288809941952652);
    assert(reader.ackDelay == 494878333);
}
