#include <iostream>
#include <string>

int main() {
    std::cout << "Welcome to miniEFS!" << std::endl;

    // TODO: Login

    std::string ipString;
    while (true)
    {
        std::cout << ">> ";
        std::cin >> ipString;
        if (ipString.rfind("cd ", 0) == 0)
        {

        }
        else if (ipString == "pwd")
        {

        }
        else if (ipString == "ls")
        {

        }
        else if (ipString.rfind("cat ", 0) == 0)
        {

        }
        else if (ipString.rfind("share ", 0) == 0)
        {

        }
        else if (ipString.rfind("mkdir ", 0) == 0)
        {

        }
        else if (ipString.rfind("mkfile ", 0) == 0)
        {

        }
        else if (ipString == "exit")
        {
            break;
        }
        else if (ipString.rfind("adduser ", 0) == 0)
        {

        }
        else
        {
            std::cout << "Unknown command!" << std::endl;
        }

    }
    return 0;
}
