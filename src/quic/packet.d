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

@VarIntLength struct ShortHeaderPacket(ulong len) //1-RTT packet
{
    ubyte headerBits;
    @EstablishedLength!(len) ubyte[len] destinationConnectionID;
}
