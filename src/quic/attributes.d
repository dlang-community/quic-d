module quic.attributes;

struct VarIntLength {};
struct FixedLength(uint len) {};
struct EstablishedLength(uint len) {};
struct TlsFrame(int type) {};
struct TlsExtension(int type) {};

template getFixedLength(T)
{
    static if(is(T == FixedLength!len, uint len))
        enum getFixedLength = len;
}

enum hasFixedLength(alias T) = is(T) && is(T == FixedLength!len, uint len);

template getEstablishedLength(T)
{
    static if(is(T == EstablishedLength!len, uint len))
        enum getEstablishedLength = len;
}

enum hasEstablishedLength(alias T) = is(T) && is(T == FixedLength!len, uint len);

template getTlsFrameType(T)
{
    static if(is(T == TlsFrame!type, int type))
        enum getTlsFrameType = type;
}

enum isTlsFrame(alias T) = is(T) && is(T == TlsFrame!type, int type);

template getTlsExtensionType(T)
{
    static if(is(T == TlsExtension!type, int type))
        enum getTlsExtensionType = type;
}

enum isTlsExtension(alias T) = is(T) && is(T == TlsFrame!type, int type);
