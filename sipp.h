#ifndef SIPP_H
#define SIPP_H

#include <stdint.h>

#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct str_s {
    char *start;
    uint32_t len;
} str_t;

// todo: as an userdata?
typedef struct headers_s {
    str_t to;
    str_t from;
    str_t contact;
    int expires;
    str_t p_access_network_info;
    str_t supported;
    str_t allow;
    str_t require;
    str_t proxy_require;
    str_t security_client;
    str_t authorization;
    str_t call_id;
    str_t cseq;
    int max_forwards;
    str_t via;
    str_t user_agent;
    int content_length;
    /* extra headers provide by user */
    void *extra;
} headers_t;

typedef int (*header_cb)(str_t *field, str_t *value, headers_t *headers);

#define MAX_HEADER_LEN 32
typedef struct node_s {
    const char *ch;
    uint32_t len; // from ch+1
    header_cb cb;
    struct node_s* childs[MAX_HEADER_LEN];
} node_t;

typedef struct sip_settings_s {
    node_t root;
} sip_settings_t;

typedef enum {
    SIP_REQUEST,
    SIP_RESPONSE,
    SIP_BOTH,
} sip_type;

/* Request Methods */
/**
 * RFC3261
 * REGISTER for registering contact information;
 * INVITE, ACK, and CANCEL for setting up sessions;
 * BYE for terminating sessions;
 * OPTIONS for querying servers about their capabilities.
 */
#define SIP_METHOD_MAP(XX)     \
  XX(0, ACK, ACK)              \
  XX(1, BYE, BYE)              \
  XX(2, CANCEL, CANCEL)        \
  XX(3, INFO, INFO)            \
  XX(4, INVITE, INVITE)        \
  XX(5, MESSAGE, MESSAGE)      \
  XX(6, NOTIFY, NOTIFY)        \
  XX(7, OPTIONS, OPTIONS)      \
  XX(8, PRACK, PRACK)          \
  XX(9, PUBLISH, PUBLISH)      \
  XX(10, REFER, REFER)         \
  XX(11, REGISTER, REGISTER)   \
  XX(12, SUBSCRIBE, SUBSCRIBE) \
  XX(13, UPDATE, UPDATE)

typedef enum {
#define XX(num, name, string) SIP_##name = num,
    SIP_METHOD_MAP(XX)
#undef XX
} sip_method;

typedef struct sip_s {
    uint8_t *data;
    uint32_t len; // data length
    sip_type type;
    uint8_t major;
    uint8_t minor;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    union {
        struct {
            int status_code;
            str_t status;
        } res;
        struct {
            sip_method method;
            str_t uri;
        } req;
    };
#pragma GCC diagnostic pop
    headers_t headers;
    char *body;
    sip_settings_t *settings;
} sip_t;

/**
 * Set extra headers, then user can manipulate it in header callback
 *   note: the `extra` need to be released by user
 * @return
 *   0 set success
 *   1 set error, maybe you need release previous extra data
 */
SIPP_PUBLIC int set_extra_hdrs(headers_t *headers, void *extra);

/**
 * set default callbacks
 * @return
 *   0  success
 *   -1 error
 *   n  number of adding callback failures
 */
SIPP_PUBLIC int set_default_cbs(sip_settings_t *settings);

/**
 * Add new callback to the beginning of callback list
 * @return
 *   0:  add new header callback successfully
 *   1:  update header callback successfully
 *   -1: error
 */
SIPP_PUBLIC int add_hdr_cb(const char *field, header_cb cb,
                           sip_settings_t *settings);
SIPP_PUBLIC void release_hdr_cbs(sip_settings_t *settings);

SIPP_PUBLIC int parse(sip_t *sip);
SIPP_PUBLIC void dump_sip(sip_t *sip);

#ifdef __cplusplus
}
#endif

#endif
