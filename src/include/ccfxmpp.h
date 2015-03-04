

#if defined(CCF_XMPP_EXPORTS)
#ifdef _WIN32
#define XMPP_API __declspec(dllexport)
#define XMPP_TEMPLATE
#else
#define XMPP_API __attribute__((__visibility__("default")))
#define XMPP_TEMPLATE
#endif
#elif defined(CCF_XMPP_IMPORTS)
#ifdef _WIN32
#define XMPP_API __declspec(dllimport)
#define XMPP_TEMPLATE extern
#else
#define XMPP_API __attribute__((__visibility__("default")))
#define XMPP_TEMPLATE
#endif
#else
#ifdef _WIN32
#define XMPP_API
#define XMPP_TEMPLATE
#else
#define XMPP_API __attribute__((__visibility__("default")))
#define XMPP_TEMPLATE
#endif
#endif
