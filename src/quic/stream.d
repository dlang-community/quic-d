module stream;
import quic.frame : StreamFrame, StreamFrameType, VarInt;

enum StreamChannel { unidirectional, bidirectional }
enum StreamOrigin { server, client }

enum denyAccess : string 
{
    cannotWrite = "Bidirectional stream not opened for writing",                            
    cannotRead =  "Bidirectional stream not opened for reading"
}

struct Stream(StreamChannel type, StreamOrigin origin)
{
    StreamFrameBuffer!(ubyte[], type) buffer;

    enum max_payload_size = 200;

    this(VarInt streamID)
    {
        static if(is(type == StreamChannel.bidirectional) &&
                is(origin == StreamOrigin.client))             
        assert(streamID & 0, "Invalid streamID");

        static if(is(type == StreamChannel.bidirectional) &&
                is(origin == StreamOrigin.server))             
        assert(streamID & 1, "Invalid streamID");

        static if(is(type == StreamChannel.unidirectional) &&
                is(origin == StreamOrigin.client))             
        assert(streamID & 2, "Invalid streamID");

        static if(is(type == StreamChannel.bidirectional) &&
                is(origin == StreamOrigin.client))             
        assert(streamID & 3, "Invalid streamID");

        buffer.currentFrame.streamID = streamID;
    
    }
    import std.sumtype;

    alias writeAccess = SumType!(ubyte[], denyAccess);
    alias readAccess = SumType!(ubyte[], denyAccess);

    static if(is(type == StreamChannel.bidirectional) ||
            (is(type == StreamChannel.unidirectional)) && is(origin == StreamOrigin.server))             
    {
        Access write(ubyte[] data, ref bool endStream=False)
        in {
            if (!sizeKnown)
                return Access(denyAccess.cannotWrite);
        } do {
            import std.range : chunks;
            auto payloadChunks = chunks(data, max_payload_size);
            while (!payloadChunks.empty)
            {
                if (endstream == true && payloadChunks.length == 1)
                    writeAFrame(payloadChunks.front, true);
                else
                    writeAFrame(payloadChunks.front, false);
                payloadChunks.popFront;
            }
        }

        Access writeAFrame(ubyte[] data, ref bool endstream=False)
        in {
            if (!sizeKnown)
                return Access(denyAccess.cannotWrite);
        } do {
            //stream is in a half-closed state
            if(data.length > max_payload_size)
                currentFrame.streamData = data[0..max_payload_size];
            else
                currentFrame.streamData = data[0..$];
            currentFrame.offset += currentFrame.streamData.length;

            if(endstream == true)
            {   //set fin bit
                currentFrame.type = currentFrame.type & 0x1;
                static if(isBidirectional)
                {
                    //bidirectional buffer is now in the open state
                    buffer.sizeKnown = true;
                }
            }
            buffer.write(currentFrame);
        }
    }
    
    static if(is(type == StreamChannel.bidirectional) ||
            (is(type == StreamChannel.unidirectional)) && is(origin == StreamOrigin.client))             
    {
        Access read(ref bool endstream)
        in {
            if (!sizeKnown)
                return Access(denyAccess.cannotRead);
        } do {
            import std.array : Appender;
            Appender!(ubyte[]) wLocal; 

            //the buffer should count 
            wLocal.reserve(buffer.dataAvailableForRead);

            while (!buffer.empty)
            {
                //the actual decoding of VarInts could be skipped
                currentFrame = buffer.read();
                wLocal ~= currentFrame.streamData;

                if(currentFrame.type & 0x1) //Size-known state
                {
                    //inform the user that all the data was read
                    endstream = true;
                    break;
                }
            }
            return Access(wLocal[]);
        }

        Access readAFrame(ref bool endstream)
        in {
            if (!sizeKnown)
                return readAccess(denyAccess.cannotRead);
        } do {
            if(!buffer.empty)
            {
                currentFrame = buffer.read();
                if(currentFrame.type & 0x1)
                    endstream = true;
                return Access(currentFrame.streamData);
            }
            return Access(null);
        }
    }
}

import std.range.primitives;                           
import std.traits : isInstanceOf, isDynamicArray;
import quic.frame_writer : QuicWriter;

alias StrFrameWithAllFields = StreamFrame!(StreamFrameType.hasLength + StreamFrameType.hasOffset);

struct StreamFrameBuffer(bufferType, StreamChannel channel)
{
    bufferType buffer;
    static if(is(channel == StreamChannel.bidirectional))
        bool sizeKnown;
    ulong dataAvailableForRead;

    StrFrameWithAllFields currentFrame;

    import quic.frame_reader;
    QuicReader!(StrFrameWithAllFields) reader;

    VarInt totalDataSize;

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
        
        void write(StrFrameWithAllFields frame)
        {
            assert(frame.offset < lastOffset,
                                    "Out-of-order frames are not supported.");
            assert(frame.offset != lastOffset + frame.streamData.length - 1,
                                                    "Malformed stream frame.");
            dataAvailableForRead += frame.offset;

            writer.getBytes(wLocal, frame);
            lastOffset = frame.offset;
            stats ~= StreamFrameStats(wLocal[].length, frame.offset);
            totalDataSize += frame.streamData.length;
            wLocal.clear();
        }

        //it is assumed that offset was read during packet parsing
        void write(ubyte[] frame, VarInt offset, VarInt dataLength)
        {
            //it is assumed that the frame was checked before calling write
            stats ~= StreamFrameStats(frame.length, frame.offset);
            buffer ~= frame;
        }
        
        void consume()
        {
            buffer.popFrontN(stats.front.frameLength); 
        }

        ubyte[] read(VarInt offset)
        {
            if(stats.empty)
                return null;
            if(stats[0].streamOffset == offset)
                return read();

            ulong lenUntilFrame; uint i;
            for(i = 0; i < stats.length; i++)
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
        StrFrameWithAllFields frame;

        reader.networkStream = frameData;
        frame.type = reader.type;
        frame.streamID = reader.streamID;
        frame.streamData = reader.streamData;
        return frame; 
    }
}
