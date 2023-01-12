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
enum SampleOffset = 4;

ubyte[] samplePacket(FrameType)(FrameType frame, uint sampleLength)
{
    /* it is assumed that the length of the packet number(part of the payload)
    it is not known at sampling time so it must be skipped (RFC9001 5.4.2)*/
    static if(is(FrameType == ShortHeaderPacket))
    {
        return frame.packetPayload[SampleOffset..SampleOffset+sampleLength];
    }

    else //LongHeader packets
    {
        return frame.packetPayload[SampleOffset..SampleOffset+sampleLength];
    }
}

enum ProtectedHeaderBits { longHeader = 0x0f, shortHeader = 0x1f }
enum PacketLengthBits = 0x3;

void maskHeader(FrameType)(ref FrameType frame, ubyte[] mask)
in {
    assert(!(is(FrameType == RetryPacket) ||
                is(FrameType == VersionNegotiationPacket)),
     "You must not mask the header of a VersionNegotiation or a Retry packet.");
} do {
    auto packetNumberLength = frame.headerBits & PacketLengthBits;
    applyHeaderBitsMask(frame, mask);

    //mask packetNumber
    for(uint i=0; i < packetNumberLength; i++)
    {
        frame.packetPayload[i] = frame.packetPayload[i] ^ mask[i];
    }

}

void unmaskHeader(FrameType)(ref FrameType frame, ubyte[] mask)
in {
    assert(!(is(FrameType == RetryPacket) ||
                is(FrameType == VersionNegotiationPacket)),
     "VersionNegotiation and Retry packets do not have a header mask.");

} do {
    applyHeaderBitsMask(frame, mask);
    auto packetNumberLength = frame.headerBits & PacketLengthBits;

    //unmask packetNumber
    for(uint i=0; i < packetNumberLength; i++)
    {
        frame.packetPayload[i] = frame.packetPayload[i] ^ mask[i];
    }
}

void applyHeaderBitsMask(FrameType)(ref FrameType frame, ubyte[] mask)
{
    static if (is(FrameType == ShortHeaderPacket)) 
    {
        frame.headerBits = frame.headerBits ^ mask[0] &
                                        ProtectedHeaderBits.shortHeader;
    }

    else
    {
        frame.headerBits = frame.headerBits ^ mask[0] &
                                        ProtectedHeaderBits.longHeader; 
    }
}
