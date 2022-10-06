module quic.frame;

alias VarInt = ulong;

struct AckFrame {
    ubyte type;
    VarInt largestAcknowledged;
    VarInt ackDelay;
    AckRange[] range;
    EcnCount[] ecnCounts;
    ubyte[] ackRanges;
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
    ubyte[] cryptoData;
}

//TLS 1.3 frames
//Reference : RFC 8446

alias CipherSuite =  ubyte[2];

struct ClientHello
{
    uint legacy_version;
    ubyte[32] random;
    //not used by QUIC
    ubyte[] legacy_session_id = null;
    //not used by QUIC
    ubyte[] legacy_compression_method = [0];
    CipherSuite[] cipher_suites;
    Extensions[] extensions;
}

struct ServerHello
{
    uint legacy_version;
    ubyte[32] random;
    //not used by QUIC
    ubyte[] legacy_compression_method = [0];
    Extensions[] extensions;
}

struct Extensions
{
    ushort extension_type;
    ubyte[] extension_data;
}

//Extensions
alias tlsVersion = ubyte[2];

struct SupportedVersions
{
    //QUIC should support TLS 1.3 by default (0x03 0x04)
    tlsVersion[] tlsVersions = [[0x3, 0x4]];
}
alias supportedGroup = ubyte[2];

struct SupportedGroups
{   //assigned value for the "x25519" elliptic-curve
    supportedGroup[] groups = [[0x00, 0x1d]];
}

struct KeyShare
{
    supportedGroup group;
    ubyte[] publicKey;
}
