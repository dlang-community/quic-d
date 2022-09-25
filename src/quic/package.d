module quic;

unittest
{
    import deimos.openssl.opensslv : OPENSSL_VERSION_AT_LEAST;
    static assert(OPENSSL_VERSION_AT_LEAST(3, 0, 5));
}

int test(bool cond)
{
    if (cond)
        return 1;
    else
        return 2;
}

unittest
{
    assert(test(true) == 1);
}
