module quic.frame_writer;

import quic.frame;
import quic.packet;
import quic.attributes;

import std.array : Appender;
alias LocalAppender = Appender!(ubyte[]);

struct QuicWriter
{
    import quic.encode : encodeVarInt;

    void getBytes(Writer, Frame)(ref Writer writer, Frame F)
    {
        LocalAppender wLocal;
        foreach(i, field; F.tupleof) 
        {
            alias attributes = __traits(getAttributes, F.tupleof[i]);

            static if (is(typeof(field) == VarInt))
            {
                encodeVarInt(wLocal, field);
            }

            else static if (is(typeof(field) == AckRange))
            {
                encodeVarInt(wLocal, field.gap);
                encodeVarInt(wLocal, field.rangeLength);
            }

            else static if ((is(typeof(field) == EcnCount)))
            {
                encodeVarInt(wLocal, field.ect0Count);
                encodeVarInt(wLocal, field.ect1Count);
                encodeVarInt(wLocal, field.ecn_ceCount);
            }
            
            else static if(__traits(isUnsigned,typeof(field)))
            {
                writeBigEndianField!(typeof(field).sizeof)(wLocal, field);
            }

            else static if (attributes.length > 0)
            {

                static if(is(attributes == VarIntLength))
                {
                    encodeVarInt(wLocal, field.length);
                    wLocal ~= field;
                }
                
                else static if(hasFixedLength!(attributes[0]))
                {
                    writeBigEndianField!(getFixedLength!(attributes[0]))(wLocal,
                                                                field.length);
                    wLocal ~= field;
                }

                else static if (hasEstablishedLength!(attributes[0]) &&
                                                        attributes.length > 0)
                {
                    wLocal ~= field;
                }
            }

            else static if(is(typeof(field) == ubyte[]))
            {
                wLocal ~= field;
            }
        }
       
        alias frameAttrs = __traits(getAttributes, F);
        static if(frameAttrs.length > 0 && isTlsFrame!(frameAttrs[0]))
        {
            writeBigEndianField!(1)(writer, getTlsFrameType!(frameAttrs[0]));
            writeBigEndianField!(getFixedLength!(frame_writer[1]))(writer, wLocal[].length);
        }

        static if(frameAttrs.length > 0 && isTlsExtension!(frameAttrs[0]))
        {
            writeBigEndianField!(2)(writer, getTlsExtensionType!frameAttrs[0]);
            writeBigEndianField!(getFixedLength!(frame_writer[1]))(writer, wLocal[].length);
        }

        writer ~= wLocal[];
    }
}

void writeBigEndianField(uint FieldLen, Writer, FieldType)(ref Writer writer,
                            FieldType field)
{
    import std.bitmanip : nativeToBigEndian;
    ubyte[FieldType.sizeof] bigEndianField = nativeToBigEndian(field);
    writer ~= bigEndianField[$-FieldLen..$];
}

unittest
{
    import quic.packet : InitialPacket;
    import std.conv : hexString;
    import std.digest : toHexString, LetterCase;

    QuicWriter writer;            
    InitialPacket packet;
    packet.headerBits = 0xc0;
    packet.destinationConnectionID = cast(ubyte[]) hexString!"0001020304050607";
    packet.sourceConnectionID = cast(ubyte[]) hexString!"635f636964";
    
    LocalAppender buffer;
    writer.getBytes(buffer, packet);
    assert(buffer[].toHexString!(LetterCase.lower) ==
                                "c00000000108000102030405060705635f63696400");
}
