module quic.frame;
import quic.attributes;

enum TlsFrameTypes {
    clientHello, serverHello
}

enum TlsExtensionTypes {
   supportedGroups = 10, supportedVersions = 43, keyShare = 51 
}

alias VarInt = ulong;

struct AckFrame {
    ubyte frameType;
    VarInt largestAcknowledged;
    VarInt ackDelay;
    AckRange[] range;
    EcnCount[] ecnCounts;
    @VarIntLength ubyte[] ackRanges;
}

struct AckRange {
    VarInt gap;
    VarInt rangeLength;
}

struct EcnCount {
    VarInt ect0Count;
    VarInt ect1Count;
    VarInt ecn_ceCount;
}

struct CryptoFrame
{
    VarInt type;
    VarInt offset;
    VarInt length;
    @VarIntLength ubyte[] cryptoData;
}

struct HandshakeDone
{
    VarInt type;
}

//TLS 1.3 frames
//Reference : RFC 8446

alias TlsData = ubyte[2];

@TlsFrame!(TlsFrameTypes.clientHello) @FixedLength!3 struct ClientHello
{
    uint legacy_version;
    ubyte[32] random;
    //not used by QUIC
    ubyte[] legacy_session_id = [0];
    //not used by QUIC
    @FixedLength!1 ubyte[] legacy_compression_method = [0];
    @FixedLength!2 ubyte[] cipher_suites = [0x13, 0x1];//TLS_AES_128_GCM_SHA256
    @FixedLength!2 ubyte[] extensionData;
}

@TlsFrame!(TlsFrameTypes.serverHello) @FixedLength!3 struct ServerHello
{
    ubyte frameType;
    uint legacy_version;
    ubyte[32] random;
    //not used by QUIC
    @FixedLength!1 ubyte[] legacy_compression_method = [0];
    @FixedLength!2 ubyte[] extensionData;
}

//Extensions

@TlsExtension!(TlsExtensionTypes.supportedVersions) @FixedLength!2 struct SupportedVersions
{
    //QUIC should support TLS 1.3 by default (0x03 0x04)
    @FixedLength!2 ubyte[] tlsVersions = [0x3, 0x4];
}

@TlsExtension!(TlsExtensionTypes.supportedGroups) @FixedLength!2 struct SupportedGroups
{   //assigned value for the "x25519" elliptic-curve
    @FixedLength!2 ubyte[] groups = [0x00, 0x1d];
}

@TlsExtension!(TlsExtensionTypes.keyShare) @FixedLength!2 struct KeyShare
{
    @FixedLength!2 ubyte[] groups = [0x00, 0x1d];
    @FixedLength!2 ubyte[] publicKey;
}
