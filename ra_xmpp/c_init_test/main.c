
#define XMPP_LIB_(x) xmpp_##x
#include <ra_xmpp.h>

#include <stdio.h>

int main(int argc, char *argv[])
{
    xmpp_context_t context;

    xmpp_context_init(&context);

    xmpp_handle_t handle = xmpp_startup(&context);
    if (handle.abstract_handle)
    {
        xmpp_shutdown_xmpp(handle);
        printf("TEST RAN OKAY\n");
    }
    else
    {
        printf("INIT TEST FAILED\n");
    }

    xmpp_context_destroy(&context);

    return 0;
}


