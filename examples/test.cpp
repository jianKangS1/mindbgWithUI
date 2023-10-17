#include <iostream>
using namespace std;
class outclass
{
public:
    int m;
    class inclass // 内部类通过parent指针访问外部类的成员，包括public、private
    {
    public:
        void set_m(int i)
        {
            outclass *parent = (outclass *)((char *)this - offsetof(outclass, in));
            parent->m = i;
        }
    } in;
};

void main()
{
    outclass out;
    out.in.set_m(123);
    cout << out.m << endl;
    system("pause");
}