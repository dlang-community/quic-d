module quic;

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
