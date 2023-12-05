#ifndef MINIDBG_ASMPARASER_HPP
#define MINIDBG_ASMPARASER_HPP

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
namespace minidbg
{
    std::vector<std::string> split(const std::string &s, char delimiter)
    {
        // spilt s into many different parts by delimiter
        std::vector<std::string> out{};
        std::stringstream ss{s};
        std::string item;

        while (std::getline(ss, item, delimiter))
        {
            out.push_back(item);
        }
        return out;
    };
    struct asm_entry
    {
        uint64_t addr;
        std::string mechine_code;
        std::string asm_code;
        std::string comment;
    };

    struct asm_head
    {
        uint64_t start_addr;
        uint64_t end_addr;
        std::string function_name;
        std::vector<asm_entry> asm_entris;
    };

    class asmparaser
    {
    public:
        std::vector<asm_head> get_asm_data(std::string file_path)
        {

            std::vector<asm_head> result;

            std::ifstream inFile(file_path);
            std::string line;

            if (!inFile)
            {
                std::cerr << "Failed to open input file." << std::endl;
                return result;
            }

            while (std::getline(inFile, line))
            {
                if (line.size() == 0)
                    continue;
                else if (line.compare(0, 11, "Disassembly") != 0)
                {
                    if (line.find('\t') == std::string::npos)
                    {
                        result.push_back(cope_asm_head(line));
                    }
                    else
                    {
                        result.back().asm_entris.push_back(cope_asm_entry(line));
                    }
                }
            }

            for (auto &head : result)
            {
                head.end_addr = head.asm_entris.back().addr;
            }

            inFile.close();
            return result;
        }

    private:
        void trimLeft(std::string &str)
        {
            // 去除左边的空格
            int index = str.find_first_not_of(' ');
            if (index != std::string::npos)
                str.erase(0, index);
        }

        void trimRight(std::string &str)
        {
            // 去除右边的空格
            int index = str.find_last_not_of(' ');
            if (index != std::string::npos)
                str.erase(index + 1);
        }
        asm_entry cope_asm_entry(std::string &command)
        {
            std::vector<std::string> args = split(command, '\t');
            if (args.back().find('#') != std::string::npos)
            {
                std::vector<std::string> temp = split(args.back(), '#');
                args.pop_back();
                args.push_back(temp[0]);
                args.push_back(temp[1]);
            }

            for (int i = 0; i < args.size(); i++)
            {
                trimLeft(args[i]);
                trimRight(args[i]);
            }
            asm_entry result;
            if (args.size() < 3)
            {
                return result;
            }
            else
            {
                result.addr = std::stol(args[0], 0, 16);
                result.mechine_code = args[1];
                result.asm_code = args[2];
                if (args.size() == 4)
                    result.comment = args[3];
                return result;
            }
        }

        asm_head cope_asm_head(std::string &command)
        {
            std::vector<std::string> temp = split(command, ' ');
            asm_head head;
            head.start_addr = std::stol(temp[0], 0, 16);
            head.function_name = temp[1].substr(1, temp[1].size() - 3);
            return head;
        }
    };

};

#endif