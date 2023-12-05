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

    class debugger
    {
    public:
        debugger(std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid}
        {
            m_asm_name = m_prog_name + ".asm";
            auto fd = open(m_prog_name.c_str(), O_RDONLY);
            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }

        void run();

    private:
        std::string m_prog_name;
        std::string m_asm_name;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
        dwarf::dwarf m_dwarf;
        elf::elf m_elf;
        uint64_t m_load_address; // 偏移量，很重要
        std::vector<asm_head> m_asm_vct;

        void handle_command(const std::string &line);

        void handle_sigtrap(siginfo_t info)
        {
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
                print_source(line_entry->file->path, line_entry->line);
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

        void continue_execution()
        {
            step_over_breakpoint();
            // continue execute the sub program
            ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
            wait_for_signal();
        }

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

        uint64_t get_pc()
        {
            return get_register_value(m_pid, reg::rip);
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

        dwarf::die get_function_from_pc(uint64_t pc)
        {
            for (auto &cu : m_dwarf.compilation_units())
            {
                if (die_pc_range(cu.root()).contains(pc))
                {
                    for (const auto &die : cu.root())
                    {
                        if (die.tag == dwarf::DW_TAG::subprogram)
                        {
                            if (die_pc_range(die).contains(pc))
                            {
                                return die;
                            }
                        }
                    }
                }
            }
            std::cout << "i am in get function from pc";
            throw std::out_of_range{"Cannot find function"};
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

        void print_source(const std::string &file_name, unsigned line, unsigned n_lines_context = 4)
        {
            // 打印源文件代码
            std::ifstream file{file_name};

            // Work out a window around the desired line
            auto start_line = (line <= n_lines_context) ? 1 : line - n_lines_context;
            auto end_line = line + n_lines_context + ((line < n_lines_context) ? n_lines_context - line : 0) + 1;

            char c{};
            auto current_line = 1u;
            // Skip lines up until start_line
            while (current_line != start_line && file.get(c))
            {
                if (c == '\n')
                {
                    ++current_line;
                }
            }

            // Output cursor if we're at the current line
            std::cout << std::dec << (current_line) << " \t" << (current_line == line ? "> " : "  ");

            // Write lines up until end_line
            while (current_line <= end_line && file.get(c))
            {
                std::cout << c;
                if (c == '\n')
                {
                    ++current_line;
                    // Output cursor if we're at the current line
                    std::cout << std::dec << (current_line) << " \t" << (current_line == line ? "> " : "  ");
                }
            }

            // Write newline and make sure that the stream is flushed properly
            std::cout << std::endl;
        }

        void print_asm(const std::string file_name, uint64_t addr, unsigned n_lines_context = 4)
        {
            for (auto asm_head_entry : m_asm_vct)
            {
                if (addr <= asm_head_entry.end_addr && addr >= asm_head_entry.start_addr)
                {
                    std::cout << "in function " << asm_head_entry.function_name << "  offset " << asm_head_entry.start_addr << "\n";
                    for (auto temp_asm_entry : asm_head_entry.asm_entris)
                    {
                        if (temp_asm_entry.addr == addr)
                        {
                            n_lines_context--;
                            std::cout << ">\t" << temp_asm_entry.asm_code << '\n';
                        }
                        else if (temp_asm_entry.addr > addr)
                        {
                            n_lines_context--;
                            std::cout << "\t" << temp_asm_entry.asm_code << '\n';
                        }

                        if (n_lines_context == 0)
                        {
                            break;
                        }
                    }

                    break;
                }
            }
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
            print_source(line_entry->file->path, line_entry->line);
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

        void print_backtrace()
        {
            auto output_frame = [frame_number = 0](auto &&func, uint64_t offset) mutable
            {
                std::cout << "frame #" << frame_number++ << ": 0x" << dwarf::at_low_pc(func) + offset
                          << ' ' << dwarf::at_name(func) << std::endl;
            };
            auto current_func = get_function_from_pc(get_offset_pc());
            output_frame(current_func, m_load_address);

            auto frame_pointer = get_register_value(m_pid, reg::rbp);
            auto return_address = read_memory(frame_pointer + 8);

            while (dwarf::at_name(current_func) != "main")
            {
                current_func = get_function_from_pc(offset_load_address(return_address));
                output_frame(current_func, m_load_address);
                frame_pointer = read_memory(frame_pointer);
                return_address = read_memory(frame_pointer + 8);
            }
        };

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
            initialise_run_objdump();
            asmparaser paraser;
            m_asm_vct = move(paraser.get_asm_data(m_asm_name));
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
    };

}

#endif
