module quic.frame_writer;

import quic.frame;
import quic.packet;
import quic.attributes;

import std.array : Appender;
alias LocalWriter = Appender!(ubyte[]);

struct QuicWriter
{
    import quic.encode : encodeVarInt;

    void getFrame(Writer, Frame)(ref Writer writer, Frame F)
    {
        LocalWriter wLocal;
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
                writeBigEndianField(wLocal, field);
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
                    writeBigEndianField(wLocal, field.length,
                                            getFixedLength!(attributes[0]));
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
            writeBigEndianField(writer, getTlsFrameType!(frameAttrs[0]), 1);
            writeBigEndianField(writer, wLocal[].length,
                                        getFixedLength!(frame_writer[1]));
        }

        static if(frameAttrs.length > 0 && isTlsExtension!(frameAttrs[0]))
        {
            writeBigEndianField(writer, getTlsExtensionType!frameAttrs[0], 2);
            writeBigEndianField(writer, wLocal[].length,
                                        getFixedLength!(frame_writer[1]));
        }

        writer ~= wLocal[];
    }
}

void writeBigEndianField(Writer, FieldType)(ref Writer writer,
                            FieldType field, int fieldLen = FieldType.sizeof)
{
    while(fieldLen)
    {
        writer ~= cast(ubyte) (field & 0xff);
        fieldLen--;
        field = field >>> 8;
    }
}
