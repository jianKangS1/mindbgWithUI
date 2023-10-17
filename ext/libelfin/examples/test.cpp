int sum(int a, int b)
{
    int c = a + b;
    c++;
    return c;
}

int main()
{
    int a = 5, b = 10;
    int c;
    c = a * 4 - b;
    c = sum(a, c);
    return 0;
}
