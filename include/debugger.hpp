#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <unordered_map>
#include <utility>
#include <string>
#include <linux/types.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cstdio>
#include <algorithm>

#include "breakpoint.hpp"
#include "registers.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"
#include "symboltype.hpp"
#include "asmparaser.hpp"

namespace minidbg
{
    bool is_prefix(const std::string &s, const std::string &of)
    {
        // if s is the prefix of of
        // s="con" of="continue" return true
        if (s.size() > of.size())
            return false;
        return std::equal(s.begin(), s.end(), of.begin());
    }

    class debugger
    {
    public:
        // 需要展示的数据
        std::vector<asm_head> m_asm_vct;
        std::vector<std::string> m_src_vct;
        std::vector<std::pair<std::string, u_int64_t>> get_ram_vct()
        {
            std::vector<std::pair<std::string, u_int64_t>> m_ram_vct;
            for (const auto &rd : g_register_descriptors)
            {
                m_ram_vct.push_back(std::make_pair(rd.name, get_register_value(m_pid, rd.r)));
            }
            return m_ram_vct;
        };

        unsigned get_src_line()
        {
            auto line_entry = get_line_entry_from_pc(get_offset_pc());
            return line_entry->line;
        }

        uint64_t get_pc()
        {
            return get_register_value(m_pid, reg::rip);
        };

        uint64_t get_rbp()
        {
            return get_register_value(m_pid, reg::rbp);
        }

        uint64_t get_rsp()
        {
            return get_register_value(m_pid, reg::rsp);
        }

        std::vector<std::pair<uint64_t, std::string>> get_backtrace_vct()
        {
            std::vector<std::pair<uint64_t, std::string>> backtrace_vct;

            auto current_func = get_function_from_pc(get_pc());

            if (current_func.end_addr == 0)
            {
                return backtrace_vct;
            }

            backtrace_vct.push_back(std::make_pair(current_func.start_addr, current_func.function_name));

            auto frame_pointer = get_register_value(m_pid, reg::rbp);
            auto return_address = read_memory(frame_pointer + 8);

            while (current_func.function_name != "main")
            {

                current_func = get_function_from_pc(return_address);
                if (current_func.end_addr == 0)
                {
                    return backtrace_vct;
                }
                backtrace_vct.push_back(std::make_pair(current_func.start_addr, current_func.function_name));

                frame_pointer = read_memory(frame_pointer);
                return_address = read_memory(frame_pointer + 8);
            }
            return backtrace_vct;
        }

        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> get_global_stack_vct(uint64_t start_addr, uint64_t end_addr)
        {
            std::vector<std::pair<uint64_t, std::vector<uint8_t>>> global_stack_vct;
            for (auto i = start_addr; i < end_addr; i += 8)
            {
                uint64_t temp_data = read_memory(i);
                std::vector<uint8_t> temp_bite_vct(8);
                // 提取uint64_t的每一个字节
                for (auto weishu = 0; weishu < 8; weishu++)
                {
                    temp_bite_vct[weishu] = (uint8_t)((temp_data >> (8 * weishu)) & 0xff);
                }

                global_stack_vct.push_back(std::make_pair(i, temp_bite_vct));
            }
            return global_stack_vct;
        }

        debugger()
        {
        }

        void initGdb(std::string prog_name, pid_t pid)
        {
            m_prog_name = std::move(prog_name);
            m_pid = pid;
            m_asm_name = m_prog_name + ".asm";
            auto fd = open(m_prog_name.c_str(), O_RDONLY);
            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};

            wait_for_signal();
            initialise_load_address();

            initialise_run_objdump();
            initialise_load_asm();

            initialise_load_src();

            std::cout << "init minigdb successfully\n";
        }

        void continue_execution()
        {
            step_over_breakpoint();
            // continue execute the sub program
            ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
            wait_for_signal();
        }

        void break_execution(std::string command)
        {

            // 0x<hexadecimal> -> address breakpoint
            // <line>:<filename> -> line number breakpoint
            // <anything else> -> function name breakpoint
            if (command[0] == '0' && command[1] == 'x')
            {
                std::string addr{command, 2}; // naively assume that the user has written 0xADDRESS like 0xff
                set_breakpoint_at_address(std::stol(addr, 0, 16) + m_load_address);
            }
            else if (command.find(':') != std::string::npos)
            {
                auto file_and_line = split(command, ':');
                set_breakpoint_at_source_file(file_and_line[0], std::stoi(file_and_line[1]));
            }
            else
            {
                set_breakpoint_at_function(command);
            }
        }

        void next_execution()
        {
            step_over();
        }

        void finish_execution()
        {
            step_out();
        }

        void step_into_execution()
        {
            step_in();
        }

        void si_execution()
        {
            single_step_instruction_with_breakpoint_check();
        }

    private:
        std::string m_prog_name;
        std::string m_asm_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        dwarf::dwarf m_dwarf;
        elf::elf m_elf;
        uint64_t m_load_address; // 偏移量，很重要

        void handle_command(const std::string &line)
        {
            // 后端实现的功能
            //  erase line backspace before and after
            std::vector<std::string> args = split(line, ' ');
            std::string command = args[0];

            if (is_prefix(command, "break"))
            {
            }
            else if (is_prefix(command, "register"))
            {
                if (is_prefix(args[1], "dump"))
                {
                    dump_registers();
                }
                else if (is_prefix(args[1], "read"))
                {
                    std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
                }
                else if (is_prefix(args[1], "write"))
                {
                    std::string val{args[3], 2}; // assume 0xVALUE
                    set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
                    std::cout << "write data " << args[3] << " into reg " << args[2] << " successfully\n";
                }
                else
                {
                    std::cout << "unknow command for register\n";
                }
            }
            else if (is_prefix(command, "symbol"))
            {
                auto syms = lookup_symbol(args[1]);
                for (auto &s : syms)
                {
                    std::cout << s.name << " " << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
                }
            }
            else if (is_prefix(command, "memory"))
            {
                std::string addr{args[2], 2}; // assume 0xADDRESS

                if (is_prefix(args[1], "read"))
                {
                    std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
                }
                if (is_prefix(args[1], "write"))
                {
                    std::string val{args[3], 2}; // assume 0xVAL
                    write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
                }
            }
            else if (is_prefix(command, "si"))
            {
                single_step_instruction_with_breakpoint_check();
                // std::cout<<get_pc()<<std::endl;
                auto offset_pc = offset_load_address(get_pc());
                auto line_entry = get_line_entry_from_pc(offset_pc);
               // print_source(line_entry->file->path, line_entry->line);
            }
            else if (is_prefix(command, "step"))
            {
                step_in();
            }
            else if (is_prefix(command, "next"))
            {
                step_over();
            }
            else if (is_prefix(command, "finish"))
            {
                step_out();
            }
            else if (is_prefix(command, "backtrace"))
            {
                // print_backtrace();
            }
            else if (is_prefix(command, "ls"))
            {

                auto line_entry = get_line_entry_from_pc(get_offset_pc());
               // print_source(line_entry->file->path, line_entry->line);
                // print_asm(m_asm_name, get_offset_pc());
            }
            else
            {
                std::cerr << "unknow command\n";
            }
        }
        void handle_sigtrap(siginfo_t info)
        {
            // 信号处理函数
            switch (info.si_code)
            {
            case SI_KERNEL:
            case TRAP_BRKPT:
            {
                auto nowpc = get_pc();
                set_pc(nowpc - 1);
                nowpc--;
                std::cout << "hit breakpoint at address 0x" << std::hex << nowpc << std::endl;
                auto offset_pc = offset_load_address(nowpc);
                auto line_entry = get_line_entry_from_pc(offset_pc);
                // print_source(line_entry->file->path, line_entry->line);
                return;
            }
            case TRAP_TRACE:
                std::cout << "get signal trap_trace" << std::endl;
                return;
            default:
                std::cout << "unknow sigtrap code" << info.si_code << std::endl;
                return;
            }
        };

        uint64_t offset_load_address(uint64_t addr)
        {
            return addr - m_load_address;
        }

        uint64_t offset_dwarf_address(uint64_t addr)
        {
            return addr + m_load_address;
        }

        uint64_t get_offset_pc()
        {
            return offset_load_address(get_pc());
        }
        uint64_t read_memory(uint64_t address)
        {
            return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
        };

        void write_memory(uint64_t address, uint64_t value)
        {
            ptrace(PTRACE_POKEDATA, m_pid, address, value);
        };

        void set_breakpoint_at_address(std::intptr_t addr)
        {
            std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
            breakpoint bp(m_pid, addr);
            bp.enable();
            m_breakpoints[addr] = bp;
        };

        void dump_registers()
        {
            for (const auto &rd : g_register_descriptors)
            {
                std::cout << rd.name << "  0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
            }
        };

        void set_pc(uint64_t pc)
        {
            set_register_value(m_pid, reg::rip, pc);
        };

        void wait_for_signal()
        {
            int wait_status;
            auto options = 0;
            waitpid(m_pid, &wait_status, options);

            auto siginfo = get_signal_info();

            switch (siginfo.si_signo)
            {
            case SIGTRAP:
                handle_sigtrap(siginfo);
                break;
            case SIGSEGV:
                std::cout << "sorry, segment fault . reason : " << siginfo.si_code << std::endl;
                break;
            default:
                std::cout << "get signal  " << strsignal(siginfo.si_signo) << std::endl;
                break;
            }
        }

        void step_over_breakpoint()
        {

            if (m_breakpoints.count(get_pc()))
            {
                auto &bp = m_breakpoints[get_pc()];

                if (bp.is_enabled())
                {
                    bp.disable();
                    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
                    wait_for_signal();
                    bp.enable();
                }
            }
        };

        asm_head get_function_from_pc(uint64_t pc)
        {
            for (auto &head : m_asm_vct)
            {
                if (pc >= head.start_addr && pc <= head.end_addr)
                {
                    return head;
                }
            }
            asm_head temp;
            temp.end_addr = 0;
            return temp;
        }

        dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc)
        {

            for (auto &cu : m_dwarf.compilation_units())
            {
                if (die_pc_range(cu.root()).contains(pc))
                {
                    auto &lt = cu.get_line_table();
                    auto it = lt.find_address(pc);
                    if (it == lt.end())
                    {
                        return lt.begin();
                    }
                    else
                    {
                        return it;
                    }
                }
            }

            throw std::out_of_range{"can't find line entry"};
        }

        dwarf::line_table::iterator get_next_line_entry_from_pc(uint64_t pc)
        {
            auto line_entry = get_line_entry_from_pc(pc);
            line_entry++;
            return line_entry;
        }


        siginfo_t get_signal_info()
        {
            siginfo_t info;
            ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
            return info;
        }

        void single_step_instruction()
        {
            // 向子进程发送信号，运行一步
            // 这个函数让子进程只执行一条指令
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
        }

        void single_step_instruction_with_breakpoint_check()
        {
            if (m_breakpoints.count(get_pc()))
            {
                step_over_breakpoint();
            }
            else
            {
                single_step_instruction();
            }
        }

        void remove_breakpoint(std::intptr_t addr)
        {
            if (m_breakpoints.at(addr).is_enabled())
            {
                m_breakpoints.at(addr).disable();
            }

            m_breakpoints.erase(addr);
        }

        void step_out()
        {
            auto frame_pointer = get_register_value(m_pid, reg::rbp);
            auto return_address = read_memory(frame_pointer + 8);

            bool should_remove_breakpoint = false;
            if (!m_breakpoints.count(return_address))
            {
                set_breakpoint_at_address(return_address);
                should_remove_breakpoint = true;
            }

            continue_execution();

            if (should_remove_breakpoint)
            {
                remove_breakpoint(return_address);
            }
        }

        void step_in()
        {
            auto line = get_line_entry_from_pc(get_offset_pc())->line;
            // std::cout <<"test"<< get_line_entry_from_pc(get_offset_pc())->line << "  " << line << "\n";
            while (get_line_entry_from_pc(get_offset_pc())->line == line)
            {
                // std::cout << get_line_entry_from_pc(get_offset_pc())->line << "  " << line << "\n";
                single_step_instruction_with_breakpoint_check();
            }

            auto line_entry = get_line_entry_from_pc(get_offset_pc());
            //print_source(line_entry->file->path, line_entry->line);
        }

        void step_over()
        {
            // 执行下一条指令，进入函数体
            // std::cout << "now pc is 0x" << std::hex << get_pc() << "\n";
            auto line_entry = get_next_line_entry_from_pc(get_offset_pc());
            auto newpc = offset_dwarf_address(line_entry->address);
            // std::cout << "my new pc is 0x" << std::hex << get_pc() << "\n";
            if (!m_breakpoints.count(newpc))
            {
                set_breakpoint_at_address(newpc);
            }
            continue_execution();

            remove_breakpoint(newpc);
            // std::cout << "after continue 0x" << std::hex << get_pc() << "\n";
        };

        void set_breakpoint_at_function(const std::string &name)
        {
            bool flag = false;
            for (const auto &cu : m_dwarf.compilation_units())
            {
                for (const auto &die : cu.root())
                {
                    if (die.has(dwarf::DW_AT::name) && at_name(die) == name)
                    {
                        flag = true;
                        auto low_pc = at_low_pc(die);
                        auto entry = get_line_entry_from_pc(low_pc);
                        ++entry;
                        set_breakpoint_at_address(offset_dwarf_address(entry->address));
                    }
                }
            }
            if (!flag)
            {
                std::cout << "fails to set breakpoint at function " << name << "\nCan't find it\n";
            }
        }

        void set_breakpoint_at_source_file(const std::string &file, unsigned line)
        {
            for (const auto &cu : m_dwarf.compilation_units())
            {
                auto rootName = at_name(cu.root());
                size_t pos = rootName.rfind('/');
                if (pos != std::string::npos && pos != rootName.size() - 1)
                {
                    rootName = rootName.substr(pos + 1);
                }

                if (file == rootName)
                {
                    const auto &lt = cu.get_line_table();

                    for (const auto &entry : lt)
                    {
                        if (entry.is_stmt && entry.line == line)
                        {
                            set_breakpoint_at_address(offset_dwarf_address(entry.address));
                            return;
                        }
                    }
                }
            }
            std::cout << "set breakpoint at function " << file << " and line " << line << " fails\n";
        }

        std::vector<symboltype::symbol> lookup_symbol(const std::string &name)
        {
            std::vector<symboltype::symbol> syms;

            for (auto &sec : m_elf.sections())
            {
                if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
                    continue;

                for (auto sym : sec.as_symtab())
                {
                    if (sym.get_name() == name)
                    {
                        auto &d = sym.get_data();
                        syms.push_back(symboltype::symbol{symboltype::to_symbol_type(d.type()), sym.get_name(), d.value});
                    }
                }
            }
            // 去重
            std::vector<symboltype::symbol>::iterator unique_end = std::unique(syms.begin(), syms.end());
            syms.erase(unique_end, syms.end());
            return syms;
        }



        void initialise_load_address()
        {
            // 初始化，获取程序的偏移量
            //  If this is a dynamic library (e.g. PIE)
            if (m_elf.get_hdr().type == elf::et::dyn)
            {
                // The load address is found in /proc/&lt;pid&gt;/maps
                std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");

                // Read the first address from the file
                std::string addr;
                std::getline(map, addr, '-');
                addr = "0x" + addr;
                m_load_address = std::stoul(addr, 0, 16);
            }
        }

        void initialise_load_asm()
        {
            asmparaser paraser;
            m_asm_vct = move(paraser.get_asm_data(m_asm_name));
            for (auto &head : m_asm_vct)
            {
                head.start_addr += m_load_address;
                head.end_addr += m_load_address;
                for (auto &entry : head.asm_entris)
                {
                    entry.addr += m_load_address;
                }
            }
        }

        void initialise_run_objdump()
        {
            std::string binaryFile = m_prog_name;
            std::string middleFile = m_prog_name + ".asm";

            // 使用 objdump 命令生成反汇编代码
            std::string command = "objdump -d " + binaryFile + "  | tail -n +4 > " + middleFile;
            int result = std::system(command.c_str());

            if (result != 0)
            {
                std::cerr << "error when run command: " + command << std::endl;
            }
        }

        void initialise_load_src()
        {
            // 获取汇编文件的路径
            auto offset_pc = offset_load_address(get_pc());
            auto line_entry = m_dwarf.compilation_units().begin()->get_line_table().begin();
            std::string file_path = std::string(line_entry->file->path);
            // std::cout<<"trying to open src "<<file_path<<"\n";

            std::ifstream inFile(file_path);
            std::string line;

            if (!inFile)
            {
                std::cerr << "Failed to open input file " << file_path << std::endl;
                return;
            }

            while (std::getline(inFile, line))
            {
                m_src_vct.push_back(line);
            }

            inFile.close();
            return;
        };
    };

}

#endif
