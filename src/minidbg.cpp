#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <sys/personality.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <stdio.h>
#include <string>

#define GL_SILENCE_DEPRECATION

#include <GLFW/glfw3.h> // Will drag system OpenGL headers

#include "debugger.hpp"
#include "breakpoint.hpp"
#include "registers.hpp"
#include "asmparaser.hpp"

using namespace minidbg;

debugger dbg;

static bool show_program = true;
static bool show_stack = true;
static bool show_src = true;
static bool show_global_stack = true;
static bool show_ram = true;
static bool show_option_bar = true;
static bool show_call_stack = true;
static bool show_demo_window = false;

// static int windows_status = (ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
static int windows_status = (ImGuiWindowFlags_None);

static void glfw_error_callback(int error, const char *description)
{
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

static void HelpMarker(const char *desc)
{
    ImGui::TextDisabled("(?)");
    if (ImGui::BeginItemTooltip())
    {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void ShowProgram(bool *p_open)
{
    ImGui::Begin("Program", p_open, windows_status);

    ImGui::SetWindowFontScale(1.5f);

    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
        ImGui::BeginChild("Program data", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);
        int i = 0;
        auto program_line = dbg.get_src_line();
        for (auto &src : dbg.m_src_vct)
        {
            if (i + 1 != program_line)
            {
                ImGui::Text("%d\t%s", ++i, src.c_str());
            }
            else
            {
                char buf[128];
                sprintf(buf, "%d\t%s", ++i, src.c_str());
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
                ImGui::Button(buf, ImVec2(-FLT_MIN, 0.0f));
                ImGui::PopStyleVar();
                ImGui::PopStyleColor();
            }
        }
        ImGui::EndChild();
    }

    ImGui::End();
}

void ShowStack(bool *p_open)
{
    ImGui::Begin("Stack", p_open, windows_status);
    ImGui::SetWindowFontScale(1.5f);

    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
        ImGui::BeginChild("Stack info", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);

        ImGui::Text("rip\t\t%lx", dbg.get_pc());
        ImGui::Text("rbp\t\t%lx", dbg.get_rbp());
        ImGui::Text("rsp\t\t%lx", dbg.get_rsp());

        ImGui::EndChild();
    }
    ImGui::End();
}

void ShowSrc(bool *p_open)
{
    ImGui::Begin("Src", p_open, windows_status);
    ImGui::SetWindowFontScale(1.5f);

    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
        ImGui::BeginChild("Src data", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);

        auto asm_addr = dbg.get_pc();

        for (auto &head : dbg.m_asm_vct)
        {
            ImGui::TextColored(ImVec4(0, 0, 1, 1), "0x%lx\t%s", head.start_addr, head.function_name.c_str());
            for (auto &line : head.asm_entris)
            {
                if (line.addr != asm_addr)
                {
                    ImGui::Text("  0x%lx\t%s", line.addr, line.asm_code.c_str());
                }
                else
                {
                    char buf[128];
                    sprintf(buf, "  0x%lx\t%s", line.addr, line.asm_code.c_str());
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                    ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
                    ImGui::Button(buf, ImVec2(-FLT_MIN, 0.0f));
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor();
                }
            }
        }

        ImGui::EndChild();
    }
    ImGui::End();
}
void ShowGlobalStack(bool *p_open)
{
    ImGui::Begin("Global Satck", p_open, windows_status);
    ImGui::SetWindowFontScale(1.5f);

    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
        ImGui::BeginChild("Global Stack info", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);

        auto rsp = dbg.get_rsp();
        auto rbp = dbg.get_rbp();
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> global_stack_vct = std::move(dbg.get_global_stack_vct(rsp - 512, rbp + 512));

        static ImGuiTableFlags flags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable;

        if (ImGui::BeginTable("global stack table", 9, flags))
        {
            ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+0", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+1", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+2", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+3", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+4", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+5", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+6", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("+7", ImGuiTableColumnFlags_WidthStretch);

            ImGui::TableHeadersRow();

            for (auto &row : global_stack_vct)
            {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (row.first != rsp && row.first != rbp)
                {
                    ImGui::Text("%lx", row.first);
                }
                else
                {

                    char buf[128];
                    sprintf(buf, "%lx", row.first);
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
                    ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
                    ImGui::Button(buf, ImVec2(-FLT_MIN, 0.0f));
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor();
                }

                u_int32_t column = 0;
                for (auto &col : row.second)
                {

                    ImGui::TableSetColumnIndex(++column);
                    ImGui::Text("%02x", col);
                }
            }

            ImGui::EndTable();
        }

        ImGui::EndChild();
    }
    ImGui::End();
}
void ShowRam(bool *p_open)
{
    ImGui::Begin("Ram", p_open, windows_status);
    ImGui::SetWindowFontScale(1.5f);

    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_None;

        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 5.0f);

        ImGui::BeginChild("Ram data", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);

        ImVec4 bgColor(139.0f / 255.0f, 0, 0, 1);
        ImGui::PushStyleColor(ImGuiCol_Text, bgColor);
        std::vector<std::pair<std::string, u_int64_t>> vct = std::move(dbg.get_ram_vct());

        for (auto p : vct)
        {
            ImGui::Text("%s\t\t0x%lx", p.first.c_str(), p.second);
        }
        ImGui::PopStyleColor();

        ImGui::EndChild();
        ImGui::PopStyleVar();
    }

    ImGui::End();
}

void ShowCallStack(bool *p_open)
{
    ImGui::Begin("Call Stack", p_open, windows_status);

    std::vector<std::pair<uint64_t, std::string>> call_stack_vct = move(dbg.get_backtrace_vct());

    ImGui::SetWindowFontScale(1.5f);
    {
        ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
        ImGui::BeginChild("Src data", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), false, window_flags);

        int index = 0;
        for (auto p : call_stack_vct)
        {
            ImGui::Text("frame#%d:0x%lx\t%s", ++index, p.first, p.second.c_str());
        }

        ImGui::EndChild();
    }
    ImGui::End();
}

void ShowOptionMainMenuBar()
{
    if (ImGui::BeginMainMenuBar())
    {
        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::BeginMenu("File"))
        {
            if (ImGui::MenuItem("Load Program"))
            {
            }

            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }

    if (ImGui::BeginMainMenuBar())
    {
        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::BeginMenu("View"))
        {
            if (ImGui::MenuItem("Format"))
            {
                ImGui::SetWindowFontScale(1.5f);
                if (ImGui::MenuItem("Dec"))
                {
                }
                if (ImGui::MenuItem("Hex"))
                {
                }
                if (ImGui::MenuItem("Bin"))
                {
                }
            }
            if (ImGui::BeginMenu("Elements"))
            {
                ImGui::SetWindowFontScale(1.5f);
                if (ImGui::MenuItem("Program", NULL, show_program))
                {
                    show_program = !show_program;
                }
                if (ImGui::MenuItem("Stack", NULL, show_stack))
                {
                    show_stack = !show_stack;
                }
                if (ImGui::MenuItem("Global Stack", NULL, show_global_stack))
                {
                    show_global_stack = !show_global_stack;
                }
                if (ImGui::MenuItem("Call Stack", NULL, show_call_stack))
                {
                    show_call_stack = !show_call_stack;
                }
                if (ImGui::MenuItem("Src", NULL, show_src))
                {
                    show_src = !show_src;
                }
                if (ImGui::MenuItem("Ram", NULL, show_ram))
                {
                    show_ram = !show_ram;
                }

                if (ImGui::MenuItem("Demo Table ", NULL, show_demo_window))
                {
                    show_demo_window = !show_demo_window;
                }

                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Layout"))
            {
                ImGui::EndMenu();
            }
            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }

    if (ImGui::BeginMainMenuBar())
    {
        ImGui::SetWindowFontScale(1.5f);
        if (ImGui::BeginMenu("Run"))
        {
            ImGui::SetWindowFontScale(1.5f);
            if (ImGui::MenuItem("Stepi"))
            {
                dbg.si_execution();
            }
            if (ImGui::MenuItem("Next"))
            {
                dbg.next_execution();
            }
            if (ImGui::MenuItem("Continue"))
            {
                dbg.continue_execution();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }
}

void ShowOptionBar(bool *p_open)
{
    ImGui::Begin("Option Bar", p_open, windows_status | ImGuiWindowFlags_NoTitleBar);
    ImGui::SetWindowFontScale(1.5f);
    ShowOptionMainMenuBar();

    if (ImGui::BeginTable("split", 10, ImGuiTableFlags_Resizable | ImGuiTableFlags_NoSavedSettings))
    {
        ImGui::TableNextColumn();
        if (ImGui::Button("file", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("start", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("next", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
            dbg.next_execution();
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("si", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
            dbg.si_execution();
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("step in", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
            dbg.step_into_execution();
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("finish", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
            dbg.finish_execution();
        };
        ImGui::TableNextColumn();
        if (ImGui::Button("continue", ImVec2(-FLT_MIN, -FLT_MIN)))
        {
            dbg.continue_execution();
        };

        ImGui::EndTable();
    }

    ImGui::End();
}

int buildWindows()
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    const char *glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window with graphics context
    GLFWwindow *window = glfwCreateWindow(1680, 896, "mingdb", nullptr, nullptr);
    if (window == nullptr)
        return 1;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();

    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;  // Enable Gamepad Controls

    // Setup Dear ImGui style
    // ImGui::StyleColorsDark();
    ImGui::StyleColorsLight();

    // Setup Platform/Renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Load Fonts
    // - If no fonts are loaded, dear imgui will use the default font. You can also load multiple fonts and use ImGui::PushFont()/PopFont() to select them.
    // - AddFontFromFileTTF() will return the ImFont* so you can store it if you need to select the font among multiple.
    // - If the file cannot be loaded, the function will return a nullptr. Please handle those errors in your application (e.g. use an assertion, or display an error and quit).
    // - The fonts will be rasterized at a given size (w/ oversampling) and stored into a texture when calling ImFontAtlas::Build()/GetTexDataAsXXXX(), which ImGui_ImplXXXX_NewFrame below will call.
    // - Use '#define IMGUI_ENABLE_FREETYPE' in your imconfig file to use Freetype for higher quality font rendering.
    // - Read 'docs/FONTS.md' for more instructions and details.
    // - Remember that in C/C++ if you want to include a backslash \ in a string literal you need to write a double backslash \\ !
    // - Our Emscripten build process allows embedding fonts to be accessible at runtime from the "fonts/" folder. See Makefile.emscripten for details.
    // io.Fonts->AddFontDefault();
    // io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\segoeui.ttf", 18.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf", 16.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/Roboto-Medium.ttf", 16.0f);
    // io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf", 15.0f);
    // ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf", 18.0f, nullptr, io.Fonts->GetGlyphRangesJapanese());
    // IM_ASSERT(font != nullptr);

    // Our state

    bool show_another_window = false;
    bool show_my_table = true;

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    while (!glfwWindowShouldClose(window))
    {

        // Poll and handle events (inputs, window resize, etc.)
        // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
        // - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
        // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
        // Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
        glfwPollEvents();

        // Start the Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (show_program)
        {
            ShowProgram(&show_program);
        }

        if (show_stack)
        {
            ShowStack(&show_stack);
        }

        if (show_src)
        {
            ShowSrc(&show_src);
        }
        if (show_global_stack)
        {
            ShowGlobalStack(&show_global_stack);
        }

        if (show_ram)
        {
            ShowRam(&show_ram);
        }
        if (show_option_bar)
        {
            ShowOptionBar(&show_option_bar);
        }
        if (show_call_stack)
        {
            ShowCallStack(&show_call_stack);
        }
        // 1. Show the big demo window (Most of the sample code is in ImGui::ShowDemoWindow()! You can browse its code to learn more about Dear ImGui!).
        if (show_demo_window)
        {
            ImGui::ShowDemoWindow(&show_demo_window);
        }

        // Rendering
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
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

        dbg.initGdb(prog, pid);
        dbg.break_execution("main");
        dbg.continue_execution();
        buildWindows();
    }
}
