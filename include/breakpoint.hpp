#ifndef MINIDBG_DREAKPOINT_HPP
#define MINIDBG_DREAKPOINT_HPP

#include <linux/types.h>
#include <utility>
#include <string>

namespace minidbg
{
    class breakpoint
    {
    public:
        breakpoint() = default;
        breakpoint(pid_t pid, std::intptr_t addr)
            : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_save_data{}
        {
        }

        void enable()
        {
            auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            m_save_data = static_cast<uint8_t>(data & 0xff);
            uint64_t int3 = 0xcc; // 系统软件中断，程序运行到这个地方，就会执行主函数的wait函数
            uint64_t data_with_int3 = ((data & ~0xff) | int3);
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

            m_enabled = true;
        };
        void disable()
        {
            // 将原来的的软件中断0xcc替换成原来的数据
            auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            auto restore_data = ((data & ~0xff) | m_save_data);
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, restore_data);

            m_enabled = false;
        };

        auto is_enabled() const -> bool { return m_enabled; }
        auto get_address() const -> intptr_t { return m_addr; }

    private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        uint8_t m_save_data;
    };
}

#endif