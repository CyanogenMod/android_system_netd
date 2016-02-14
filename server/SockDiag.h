#include <functional>

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>

struct inet_diag_msg;
class SockDiagTest;

class SockDiag {

  public:
    static const int kBufferSize = 4096;
    typedef std::function<int(uint8_t proto, const inet_diag_msg *)> DumpCallback;

    struct DestroyRequest {
        nlmsghdr nlh;
        inet_diag_req_v2 req;
    } __attribute__((__packed__));

    SockDiag() : mSock(-1), mWriteSock(-1), mSocketsDestroyed(0) {}
    bool open();
    virtual ~SockDiag() { closeSocks(); }

    int sendDumpRequest(uint8_t proto, uint8_t family, const char *addrstr);
    int readDiagMsg(uint8_t proto, DumpCallback callback);
    int sockDestroy(uint8_t proto, const inet_diag_msg *);
    int destroySockets(const char *addrstr);

  private:
    int mSock;
    int mWriteSock;
    int mSocketsDestroyed;
    int destroySockets(uint8_t proto, int family, const char *addrstr);
    bool hasSocks() { return mSock != -1 && mWriteSock != -1; }
    void closeSocks() { close(mSock); close(mWriteSock); mSock = mWriteSock = -1; }
};
