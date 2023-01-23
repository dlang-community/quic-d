module quic.frame_reader;

import quic.frame;
import quic.packet;
import quic.attributes;

struct QuicReader(FrameType)
{
    import quic.decode : decodeVarInt;

    ubyte[] networkStream;
    ulong bufIndex;

    this(ubyte[] networkStream, ulong bufIndex)
    {
        this.networkStream = networkStream; 
        this.bufIndex = bufIndex;
    }

    alias read = opDispatch;

    auto opDispatch(string name)() {
            alias FieldType = typeof(__traits(getMember, FrameType, name));

            alias attributes = __traits(getAttributes, mixin(FrameType.stringof, '.', name));

            enum errorPrefix() = "Field "
                ~ FrameType.stringof ~ '.' ~ name
                ~ " of type " ~ FieldType.stringof
                ~ " with attributes " ~ attributes.stringof;

            FieldType value;

            static if (is(FieldType == VarInt))
            {
                static assert(attributes.length == 0, errorPrefix!() ~ ": no attributes allowed");
                decodeVarInt(value, networkStream, bufIndex);
                return value;
            }

            else static if (is(FieldType == AckRange))
            {
                static assert(attributes.length == 0, errorPrefix!() ~ ": no attributes allowed");
                decodeVarInt(value.gap, networkStream, bufIndex);
                decodeVarInt(value.rangeLength, networkStream, bufIndex);
                return value;
            }

            else static if ((is(FieldType == EcnCount)))
            {
                static assert(attributes.length == 0, errorPrefix!() ~ ": no attributes allowed");
                decodeVarInt(value.ect0Count, networkStream, bufIndex);
                decodeVarInt(value.ect1Count, networkStream, bufIndex);
                decodeVarInt(value.ecn_ceCount, networkStream, bufIndex);
                return value;
            }

            else static if (is(FieldType == ubyte[]))
            {
                static assert(attributes.length == 1, errorPrefix
                    ~ ": must have exactly one attribute @VarIntLength or @FixedLength!n");

                static if(is(attributes[0] == VarIntLength))
                {
                    VarInt len;
                    decodeVarInt(len, networkStream, bufIndex);
                    bufIndex += len; 
                    return networkStream[bufIndex-len..bufIndex];
                }

                static if(hasFixedLength!(attributes[0]))
                {
                    auto lenOfLength = getFixedLength!(attributes[0]);
                    auto len = readBigEndianField(networkStream, bufIndex, lenOfLength);
                    bufIndex += len;
                    return networkStream[bufIndex-len..bufIndex];
                }
            }

            else static if (is(FieldType == ubyte[len], size_t len))
            {
                bufIndex += len;
                return networkStream[bufIndex-len..bufIndex];
            }

            else static assert(0, errorPrefix!() ~ " is not supported!");
        }
}

ulong readBigEndianField(ubyte[] networkStream, ref ulong bufIndex, uint len)
{
    import std.bitmanip : swapEndian;
    ulong field;
    while(len)
    {
        field = networkStream[bufIndex] + (field << 8);
        len--; 
        bufIndex++;
    }
    return field;
}

unittest
{
    import std.conv : hexString;

    ubyte[] networkStream = cast(ubyte[]) hexString!"c2197c5eff14e88c";
    networkStream ~= cast(ubyte[]) hexString!"9d7f3e7d";
    ulong bufIndex;
    auto reader = QuicReader!AckFrame(networkStream, bufIndex);
    assert(reader.largestAcknowledged == 151288809941952652);
    assert(reader.ackDelay == 494878333);
}
