#include "transparent_proxy.hpp"



int main()
{
    TransparentProxy proxy("0.0.0.0", 8000);

    proxy.add_allowed_host("vk.com"); // any valid std::regex
    proxy.add_allowed_url("/.*\\.js$");
    proxy.add_allowed_url("/.*\\.png$");
    proxy.add_allowed_url("/.*\\.jpeg$");

    proxy.run();


    return 0;
}
