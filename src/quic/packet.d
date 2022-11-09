module quic.packet;

import quic.attributes;

mixin template BaseLongHeaderPacket()
{
    ubyte headerBits;
    uint quicVersion = 0x00000001;
    @FixedLength!1 ubyte[] destinationConnectionID;
    @FixedLength!1 ubyte[] sourceConnectionID;
}

@VarIntLength struct InitialPacket
{
    mixin BaseLongHeaderPacket;
    //only added for compatibility reasons
    ubyte[] tokenLength = [0x0];
    @VarIntLength ubyte[] packetPayload;
}

@VarIntLength struct HandshakePacket
{
    mixin BaseLongHeaderPacket;
    @VarIntLength ubyte[] packetPayload;
}

@VarIntLength struct ZeroRTTPacket
{
    mixin BaseLongHeaderPacket;
    @VarIntLength ubyte[] packetPayload;
}

@VarIntLength struct RetryPacket
{
    mixin BaseLongHeaderPacket;
    //TODO : add the Retry Token
    @FixedLength!8 ubyte[] retryIntegrityTag;
}

@VarIntLength struct VersionNegotiationPacket
{
    mixin BaseLongHeaderPacket;
    @FixedLength!4 ubyte[] supportedVersion;
}

@VarIntLength struct ShortHeaderPacket(ulong len) //1-RTT packet
{
    ubyte headerBits;
    @EstablishedLength!(len) ubyte[len] destinationConnectionID;
    ubyte[] packetPayload;
}

ubyte[] samplePacket(FrameType)(FrameType frame, uint sampleLength)
{
    /* it is assumed that the length of the packet number(part of the payload)
    it is not known at sampling time so it must be skipped (RFC9001 5.4.2)*/
    static if(is(FrameType == ShortHeaderPacket))
    {
        return frame.packetPayload[5..5+sampleLength];
    }

    else //LongHeader packets
    {
        return frame.packetPayload[7..7+sampleLength];
    }
}

void maskHeader(FrameType)(ref FrameType frame, ubyte[] mask)
in {
    assert(!(is(FrameType == RetryPacket) ||
                is(FrameType == VersionNegotiationPacket)),
     "You must not mask the header of a VersionNegotiation or a Retry packet.");
} do {
    applyMask(frame, mask);
    frame.headerBits = frame.headerBits & mask[0];
}

void unmaskHeader(FrameType)(ref FrameType frame, ubyte[] mask)
in {
    assert(!(is(FrameType == RetryPacket) ||
                is(FrameType == VersionNegotiationPacket)),
     "VersionNegotiation and Retry packets do not have a header mask.");

} do {
    frame.headerBits = frame.headerBits & mask[0];
    applyMask(frame, mask);
}

void applyMask(FrameType)(ref FrameType frame, ubyte[] mask)
{
    auto packetNumberLength = frame.headerBits & 0x3;

    static if(is(FrameType == ShortHeaderPacket))
    {
        frame.headerBits = frame.headerBits & 0x5;
    }

    else
    {
        frame.headerBits = frame.headerBits & 0x4;
    }

    for(int i=0; i<packetNumberLength; i++)
    {
        frame.packetPayload[i] = frame.packetPayload[i] ^ mask[i];
    }
}
