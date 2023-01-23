module quic.attributes;

struct VarIntLength {}
struct FixedLength(uint len) {}
struct TlsFrame(int type) {}
struct TlsExtension(int type) {}

template getFixedLength(T)
{
    static if(is(T == FixedLength!len, uint len))
        enum getFixedLength = len;
}

enum hasFixedLength(T) = is(T == FixedLength!len, uint len);

template getTlsFrameType(T)
{
    static if(is(T == TlsFrame!type, int type))
        enum getTlsFrameType = type;
}

enum isTlsFrame(T) = is(T == TlsFrame!type, int type);

template getTlsExtensionType(T)
{
    static if(is(T == TlsExtension!type, int type))
        enum getTlsExtensionType = type;
}

enum isTlsExtension(T) = is(T == TlsExtension!type, int type);
