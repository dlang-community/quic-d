module stream;
import quic.frame : StreamFrame;

enum QuicStreamDirection { unidirectional, bidirectional }

enum QuicStreamOrigin { server, client }

struct Stream(type)
{
    StreamFrame!(type) frame;

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
                getOrigin == QuicStreamOrigin.Client :
                getOrigin == QuicStreamOrigin.Server;
        }
        
        return true;
    }
}

