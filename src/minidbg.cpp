#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <sys/personality.h>

#include "linenoise.h"
#include "debugger.hpp"
#include "breakpoint.hpp"
#include "registers.hpp"
#include "asmparaser.hpp"

using namespace minidbg;



bool is_prefix(const std::string &s, const std::string &of)
{
    // if s is the prefix of of
    // s="con" of="continue" return true
    if (s.size() > of.size())
        return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::handle_command(const std::string &line)
{
    // erase line backspace before and after
    std::vector<std::string> args = split(line, ' ');
    std::string command = args[0];

    if (is_prefix(command, "continue"))
    {
        continue_execution();
    }
    else if (is_prefix(command, "break"))
    {
        // 0x<hexadecimal> -> address breakpoint
        // <line>:<filename> -> line number breakpoint
        // <anything else> -> function name breakpoint

        if (args[1][0] == '0' && args[1][1] == 'x')
        {
            std::string addr{args[1], 2}; // naively assume that the user has written 0xADDRESS like 0xff
            set_breakpoint_at_address(std::stol(addr, 0, 16) + m_load_address);
        }
        else if (args[1].find(':') != std::string::npos)
        {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_file(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else
        {
            set_breakpoint_at_function(args[1]);
        }
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
        print_source(line_entry->file->path, line_entry->line);
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
        print_backtrace();
    }
    else if (is_prefix(command, "ls"))
    {

        auto line_entry = get_line_entry_from_pc(get_offset_pc());
        print_source(line_entry->file->path, line_entry->line);
        print_asm(m_asm_name, get_offset_pc());
    }
    else
    {
        std::cerr << "unknow command\n";
    }
}

void debugger::run()
{

    wait_for_signal();
    initialise_load_address();
    initialise_load_asm();
    char *line = nullptr;
    while ((line = linenoise("minidbg>")) != nullptr)
    {
        handle_command(line);
        linenoiseHistoryAdd(line); //将刚刚输入的指令加入到历史
        linenoiseFree(line); // free memory space of line
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0)
    {
        personality(ADDR_NO_RANDOMIZE); // 关闭随机内存地址的分配
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1)
    {
        // parent
        std::cout << "start debugging process " << pid << "\n";
        debugger dgb{prog, pid};
        dgb.run();
    }
}
