module stream;
import quic.frame : StreamFrame;

enum QuicStreamDirection { unidirectional, bidirectional }

enum QuicStreamOrigin { server, client }

enum QuicStreamFrameType {hasLength = 2, hasOffset = 4}

struct Stream(type)
{
    auto getDirection()
    {
        return frame.streamID & 0x2 ?
        QuicStreamDirection.unidirectional :
        QuicStreamDirection.bidirectional;
    }

    auto getOrigin()
    {
        return frame.streamID & 0x1 ?
        QuicStreamOrigin.server :
        QuicStreamDirection.client;
    }

    bool wasEverWritable(bool isServer)
    {
        if (getDirection == QuicStreamDirection.unidirectional)
        {
            return isServer ?
                getOrigin == QuicStreamOrigin.Server :
                getOrigin == QuicStreamOrigin.Client;
        }
        
        return true;
    }

    bool wasEverReadable(bool isServer)
    {
        if (getDirection == QuicStreamDirection.unidirectional)
        {
            return isServer ?
                getOrigin == QuicStreamOrigin.Server :
                getOrigin == QuicStreamOrigin.Client;
        }
        
        return true;
    }
}

import std.range.primitives;                           
import std.traits : isInstanceOf;

struct StreamFrameBuffer(bufferType)
{
    bufferType buffer;
    import quic.frame_reader;
    QuicReader reader;

    static if(isDynamicArray!bufferType && is(ElementType!(bufferType) == ubyte))
    {
        struct StreamFrameStats 
        {
            VarInt frameLength;
            VarInt streamOffset;
        }

        StreamFrameStats[] stats; 
        QuicWriter writer;
        VarInt lastOffset; 
        import std.array : Appender;
        Appender!(ubyte[]) wLocal; 
        
        void write(StreamFrame frame)
        {
            assert(frame.offset < lastOffset,
                                    "Out-of-order frames are not supported.");
            assert(frame.offset != lastOffset + frame.streamData.length - 1,
                                                    "Malformed stream frame.");
            writer.getBytes(wLocal, frame);
            lastOffset == offset;
            stats ~= StreamFrameStats(wLocal[].length, frame.offset);
            wLocal.clear();
        }

        //it is assumed that offset was read during packet parsing
        void write(ubyte[] frame, VarInt offset)
        {
            //it is assumed that the frame was checked before calling write
            stats ~= StreamFrameStats(frame.length, frame.offset);
            buffer ~= frame;
        }
        
        void consume()
        {
            buffer.popFrontN(stats.front.frameLength);
        }

        ubyte[] read(offset)
        {
            if(stats.empty)
                return null;
            if(stats[0].streamOffset == offset)
                return read();

            ulong lenUntilFrame; uint i;
            for(i = 0; i<stats.length; i++)
            {
                if(stats.streamOffset == offset)
                    break;
                lenUntilFrame += elem.frameLength;
            }

            if(i == 0)
                return null;

            return buffer[lenUntilFrame..lenUntilFrame+stats[i].frameLength];
        }

        ubyte[] read()
        {
            if(stats.empty)
                return null;
            return buffer[0..stats[0].frameLength];
        }

        auto read()
        {
            return readFrameStruct(buffer[0..stats[0].frameLength]);
        }
    }

    static if(isInputRange!bufferType && isInstanceOf!(StreamFrame,
                                                    ElementType!(bufferType)))
    {
        //acknowledges a single streamFrame
        void consume(VarInt offset)
        {
            assert(buffer.front.offset == offset, "Invalid offset!");
            buffer.popFront();
        }
    }

    static if(isInputRange!bufferType && is(ElementType!(bufferType) ==
                                                                ubyte[]))
    {
        auto read()
        {
           return readFrameStruct(bufferType.front);
        }
    }

    auto readFrameStruct(ubyte[] frameData)
    {
        StreamFrame!(cast(VarInt) (QuicStreamFrameType.hasLength +
                                        QuicStreamFrameType.hasOffset)) frame;
        reader.networkStream = frameData;
        frame.type = reader.type;
        frame.streamID = reader.streamID;
        frame.streamData = reader.streamData;
    }
}
