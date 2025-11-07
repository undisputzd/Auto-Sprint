#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <memory>
#include <stdexcept>

namespace Config
{
    std::string mc_version;
    constexpr const char* TARGET_VERSION = "1.21.11401.0";
    constexpr DWORD LOOP_DELAY_MS = 25;
}

namespace Utils
{
    class ProcessPipe
    {
    public:
        ProcessPipe() : stdout_read(nullptr), stdout_write(nullptr) {}
        ~ProcessPipe() { cleanup(); }

        std::string execute(const std::string& command)
        {
            if (!initialize()) return "";

            STARTUPINFOA si = { sizeof(si) };
            PROCESS_INFORMATION pi = { 0 };

            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = stdout_write;
            si.hStdError = stdout_write;

            if (!CreateProcessA(nullptr, const_cast<LPSTR>(command.c_str()),
                nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            {
                return "";
            }

            CloseHandle(stdout_write);
            stdout_write = nullptr;

            std::string result = read_output();

            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            return sanitize(result);
        }

    private:
        HANDLE stdout_read;
        HANDLE stdout_write;

        bool initialize()
        {
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
            if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0))
                return false;
            SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
            return true;
        }

        std::string read_output()
        {
            std::string result;
            char buffer[4096];
            DWORD bytes_read;

            while (ReadFile(stdout_read, buffer, sizeof(buffer) - 1, &bytes_read, nullptr) && bytes_read > 0)
            {
                buffer[bytes_read] = '\0';
                result.append(buffer, bytes_read);
            }

            return result;
        }

        std::string sanitize(const std::string& str)
        {
            std::string cleaned = str;
            cleaned.erase(std::remove_if(cleaned.begin(), cleaned.end(),
                [](unsigned char c) { return std::isspace(c) || !std::isprint(c); }), cleaned.end());
            return cleaned;
        }

        void cleanup()
        {
            if (stdout_read) CloseHandle(stdout_read);
            if (stdout_write) CloseHandle(stdout_write);
        }
    };

    std::string get_minecraft_version()
    {
        ProcessPipe pipe;
        return pipe.execute("powershell -NoProfile -Command \"& {Get-AppxPackage -Name Microsoft.MinecraftUWP | Select-Object -ExpandProperty Version}\"");
    }

    std::vector<int> parse_version(const std::string& version)
    {
        std::vector<int> parts;
        std::stringstream ss(version);
        std::string segment;

        while (std::getline(ss, segment, '.'))
        {
            try { parts.push_back(std::stoi(segment)); }
            catch (...) { parts.push_back(0); }
        }

        return parts;
    }

    bool is_legacy_version(const std::string& version)
    {
        auto current = parse_version(version);
        auto target = parse_version(Config::TARGET_VERSION);
        return current <= target;
    }
}

namespace Keybinds
{
    struct Keys
    {
        int sprint = 0;
        int forward = 0;
    };

    bool parse_options_file(const std::filesystem::path& path, Keys& keys)
    {
        std::ifstream file(path);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line))
        {
            if (line.find("keyboard_type_0_key.sprint:") != std::string::npos)
            {
                size_t pos = line.find(':');
                if (pos != std::string::npos)
                {
                    try { keys.sprint = std::stoi(line.substr(pos + 1)); }
                    catch (...) {}
                }
            }
            if (line.find("keyboard_type_0_key.forward:") != std::string::npos)
            {
                size_t pos = line.find(':');
                if (pos != std::string::npos)
                {
                    try { keys.forward = std::stoi(line.substr(pos + 1)); }
                    catch (...) {}
                }
            }
        }

        return (keys.sprint != 0 && keys.forward != 0);
    }

    Keys load_from_uwp()
    {
        Keys keys;
        char* localAppData = nullptr;
        size_t size;

        if (_dupenv_s(&localAppData, &size, "LOCALAPPDATA") != 0 || !localAppData)
            return keys;

        std::filesystem::path options_path = std::filesystem::path(localAppData) /
            "Packages/Microsoft.MinecraftUWP_8wekyb3d8bbwe/LocalState/games/com.mojang/minecraftpe/options.txt";

        free(localAppData);
        parse_options_file(options_path, keys);
        return keys;
    }

    Keys load_from_preview()
    {
        Keys keys;
        char* appData = nullptr;
        size_t size;

        if (_dupenv_s(&appData, &size, "APPDATA") != 0 || !appData)
            return keys;

        std::string base_path = std::string(appData) + "\\Minecraft Bedrock\\Users";
        free(appData);

        WIN32_FIND_DATAA find_data;
        HANDLE find_handle = FindFirstFileA((base_path + "\\*").c_str(), &find_data);

        if (find_handle == INVALID_HANDLE_VALUE)
            return keys;

        do
        {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;

            std::string dir_name = find_data.cFileName;
            if (dir_name == "." || dir_name == "..")
                continue;

            if (!std::all_of(dir_name.begin(), dir_name.end(), ::isdigit))
                continue;

            std::filesystem::path options_path = base_path + "\\" + dir_name +
                "\\games\\com.mojang\\minecraftpe\\options.txt";

            if (parse_options_file(options_path, keys))
                break;

        } while (FindNextFileA(find_handle, &find_data));

        FindClose(find_handle);
        return keys;
    }

    Keys load()
    {
        if (Utils::is_legacy_version(Config::mc_version))
            return load_from_uwp();
        else
            return load_from_preview();
    }
}

namespace Input
{
    bool is_in_menu()
    {
        CURSORINFO cursor = { sizeof(cursor) };
        return GetCursorInfo(&cursor) && (cursor.flags == CURSOR_SHOWING);
    }

    void toggle_sprint(int sprint_key, int forward_key)
    {
        if (!sprint_key || !forward_key || is_in_menu())
            return;

        if (GetAsyncKeyState(forward_key) & 0x8000)
            keybd_event(sprint_key, 0, 0, 0);
        else
            keybd_event(sprint_key, 0, KEYEVENTF_KEYUP, 0);
    }
}

int main()
{
    SetConsoleTitleA("Auto Sprint");

    Config::mc_version = Utils::get_minecraft_version();
    std::cout << "[+] Minecraft Version: " << Config::mc_version << std::endl;

    auto keys = Keybinds::load();

    if (!keys.sprint || !keys.forward)
    {
        std::cerr << "[-] Failed to load keybinds" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[+] Sprint Key: " << keys.sprint << std::endl;
    std::cout << "[+] Forward Key: " << keys.forward << std::endl;
    std::cout << "[+] Auto Sprint Active\n" << std::endl;

    while (true)
    {
        Input::toggle_sprint(keys.sprint, keys.forward);
        Sleep(Config::LOOP_DELAY_MS);
    }

    return EXIT_SUCCESS;
}