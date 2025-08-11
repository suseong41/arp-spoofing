#include <string>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

std::string getMyIp(const std::string& interfaceName);
std::string getMyMac(const std::string& interfaceName);
