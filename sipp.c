#include "sipp.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char tokens[0x100] = {
    /*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
    0, 0, 0, 0, 0, 0, 0, 0,
    /*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
    0, 0, 0, 0, 0, 0, 0, 0,
    /*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
    0, 0, 0, 0, 0, 0, 0, 0,
    /*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
    0, 0, 0, 0, 0, 0, 0, 0,
    /*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
    ' ', '!', 0, '#', '$', '%', '&', '\'',
    /*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
    0, 0, '*', '+', 0, '-', '.', 0,
    /*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
    '0', '1', '2', '3', '4', '5', '6', '7',
    /*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
    '8', '9', 0, 0, 0, 0, 0, 0,
    /*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
    0, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    /*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    /*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    /*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
    'x', 'y', 'z', 0, 0, 0, '^', '_',
    /*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    /* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    /* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    /* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
    'x', 'y', 'z', 0, '|', 0, '~', 0};

// typedef enum {
//     h_general
// } header_state_e;

static const char *method_strings[] = {
#define XX(num, name, string) #string,
    SIP_METHOD_MAP(XX)
#undef XX
};

typedef enum {
    start_req_or_res,
    req_or_res_S,
    SI,
    SIP,
    sip_slash,
    sip_major,
    sip_dot,
    res_sip_minor,
    res_status_code,
    res_status_code_end,
    res_status_start,
    res_status,
    res_line_almost_done,
    start_req,
    req_method,
    req_space_before_url,
    req_url_start,
    req_url,
    req_S,
    req_line_CR,
    req_line_almost_done,
    /* header related */
    header_field_start,
    header_field,
    header_value_discard_ws,
    header_value_discard_ws_almost_done,
    header_value_start,
    header_value,
    header_value_discard_lws, // linear white space
    header_almost_done,
    headers_done,
    body_start,
    message_done,
} state_e;

/**
Header Name (Long Format) Compact Format
Call-ID i
Contact m
Content-Encoding e
Content-Length l
Content-Type c
From f
Subject s
Supported k
To t
Via v
*/

/* compact format to long format */
static const char *cpt2long_map[26] = {
    0, // a
    0,
    "content-type", /* c */
    0,
    "content-encoding", // e
    "from", // f
    0,
    0,
    "call-id", /* i */
    0,
    "supported", /* k */
    "content-length", /* l */
    "contact", /* m */
    0,
    0, /* o */
    0,
    0,
    0, /* r */
    "subject", /* s */
    "to", /* t */
    0,
    "via", /* v */
};

/**
 * try to find header callback
 * @param
 *  clen: the consumed length
 * @return
 */
static inline header_cb find_header_callback(uint8_t *field, int len,
                                             sip_settings_t *settings,
                                             int *clen)
{
    node_t *next = &settings->root, *pre = NULL;
    int idx = 0;
    *clen = 0;
    while (idx < len && field[idx] != ':' && next) {
        pre = next;
        next = pre->childs[tolower(field[idx]) - 'a'];
        // if (next) printf("%d:%c;", idx, *next->ch);
        ++idx;
    }
    // printf("idx=%d\n", idx);
    *clen = idx;
    if (idx >= len) {
        // ie. field[idx-1] != ':', error
        return NULL;
    }
    if (field[idx] == ':') {
        if (next) {
            return next->cb;
        } else {
            // 回溯
        }
    }
    // 回溯
    if (pre->len > 0) {
        // 值得回溯
        idx -= 1;
        uint32_t i;
        for (i = 1; i <= pre->len && idx < len && field[idx] != ':'
                    && tolower(field[idx]) == pre->ch[i];
             i++, idx++) {}
        *clen = idx;
        if (i > pre->len && field[idx] == ':') {
            return pre->cb;
        }
    }
    // 未注册相应回调
    return NULL;
}

static inline void global_header_callback(str_t *field, str_t *value,
                                          header_cb hdr_cb, headers_t *headers)
{
    if (hdr_cb)
        hdr_cb(field, value, headers);
    else {
        printf("warning: no suitable callback for (%.*s: %.*s) found\n",
               field->len, field->start, value->len, value->start);
    }
    hdr_cb = NULL;
}

int parse(sip_t *sip)
{
    uint8_t *data = sip->data;
    uint32_t len = sip->len;
    state_e state = start_req_or_res; // set init
    str_t hdr_field, hdr_value;
    header_cb hdr_cb = NULL;
    int left, right;

    for (uint32_t idx = 0; idx < len; idx++) {
        char ch = data[idx];
    reexec:
        switch (state) {
        case start_req_or_res: {
            if (ch == CR || ch == LF) break;
            if (ch == 'S') {
                state = req_or_res_S;
            } else {
                sip->type = SIP_REQUEST;
                state = start_req;
                goto reexec;
            }

            break;
        }
        case req_or_res_S: {
            if (ch == 'I') {
                sip->type = SIP_RESPONSE;
                state = SI;
            } else {
                if (ch != 'U') { // unlikely
                    // invalid constant
                    goto error;
                }

                sip->type = SIP_REQUEST;
                sip->req.method = SIP_SUBSCRIBE;
                state = req_method;
                goto reexec;
            }
            break;
        }
        case start_req: {
            if (ch == CR || ch == LF) break;

            switch (ch) {
            case 'A':
                sip->req.method = SIP_ACK;
                break;
            case 'B':
                sip->req.method = SIP_BYE;
                break;
            case 'C':
                sip->req.method = SIP_CANCEL;
                break;
            case 'I':
                sip->req.method = SIP_INFO; /* or INVITE */
                break;
            case 'M':
                sip->req.method = SIP_MESSAGE;
                break;
            case 'N':
                sip->req.method = SIP_NOTIFY;
                break;
            case 'O':
                sip->req.method = SIP_OPTIONS;
                break;
            case 'P':
                sip->req.method = SIP_PRACK; /* or PUBLISH */
                break;
            case 'R':
                if (idx + 2 >= len || data[idx + 1] != 'E') {
                    goto error;
                }
                switch (data[idx + 2]) {
                case 'F':
                    sip->req.method = SIP_REFER;
                    break;
                case 'G':
                    sip->req.method = SIP_REGISTER;
                    break;
                default:
                    goto error;
                }
                break;
            case 'S':
                sip->req.method = SIP_SUBSCRIBE;
                break;
            case 'U':
                sip->req.method = SIP_UPDATE;
                break;
            default:
                // invalid method
                goto error;
            }
            state = req_method;

            // now we can trigger callback

            break;
        }
        case SI: {
            if (ch != 'P') {
                goto error;
            }
            state = SIP;
            break;
        }
        case SIP: {
            if (ch != '/') {
                goto error;
            }
            state = sip_slash;
            break;
        }
        case sip_slash: {
            if (!isdigit(ch)) {
                goto error;
            }
            sip->major = ch - '0';
            state = sip_major;
            break;
        }
        case sip_major: {
            if (ch != '.') {
                goto error;
            }
            state = sip_dot;
            break;
        }
        case sip_dot: {
            if (!isdigit(ch)) {
                goto error;
            }
            sip->minor = ch - '0';
            if (sip->type == SIP_REQUEST) {
                state = req_line_CR;
            } else if (sip->type == SIP_RESPONSE) {
                state = res_sip_minor;
            } else {
                goto error;
            }
            break;
        }
        case res_sip_minor: {
            if (ch != ' ') {
                goto error;
            }
            state = res_status_code;
            break;
        }
        case res_status_code: {
            if (idx + 2 >= len) {
                goto error;
            }
            if (!isdigit(ch) || !isdigit(data[idx + 1])
                || !isdigit(data[idx + 2])) {
                // invalid token
                goto error;
            }

            sip->res.status_code = (ch - '0') * 100 + (data[idx + 1] - '0') * 10
                                 + data[idx + 2] - '0';

            // TODO: check the value of status code
            idx += 2;
            state = res_status_code_end;
            break;
        }
        case res_status_code_end: {
            if (data[idx] != ' ') {
                goto error;
            }
            state = res_status_start;
            break;
        }
        case res_status_start: {
            left = idx;
            // fall through
        }
        case res_status: {
            while (idx + 1 < len && data[idx + 1] != CR
                   && data[idx + 1] != LF) {
                idx++;
            }
            if (idx + 1 == len) {
                goto error;
            }
            right = idx;
            sip->res.status.start = (char *)data + left;
            sip->res.status.len = right - left + 1;
            idx++;
            if (data[idx] == CR) {
                state = res_line_almost_done;
                break;
            }
            if (data[idx] == LF) {
                state = res_line_almost_done;
                goto reexec;
            }
            // error?
            goto error;
        }
        case res_line_almost_done: {
            if (ch != LF) {
                goto error;
            }
            state = header_field_start;
            break;
        }
        case req_method: {
            /* second letter */
            size_t method_len = strlen(method_strings[sip->req.method]);
            if (idx - 1 + method_len > len) {
                goto error;
            }
            if (strncmp((char *)data + idx - 1, method_strings[sip->req.method],
                        method_len)
                != 0) {
                // invalid method
                goto error;
            }
            idx += method_len - 1;
            // fall through
        }
        case req_space_before_url: {
            if (data[idx] != ' ') {
                goto error;
            }
            state = req_url_start;
            break;
        }
        case req_url_start: {
            // TODO: add check
            left = idx;
            state = req_url;
            // fall through
        }
        case req_url: {
            if (ch == ' ') {
                sip->req.uri.start = (char *)data + left;
                sip->req.uri.len = idx - left;
                idx++;
                if (data[idx] != 'S') {
                    goto error;
                }
                state = req_S;
            }
            break;
        }
        case req_S: {
            if (ch != 'I') {
                goto error;
            }
            state = SI;
            break;
        }
        case req_line_CR: {
            if (ch != CR) {
                goto error;
            }
            state = req_line_almost_done;
            break;
        }
        case req_line_almost_done: {
            if (ch != LF) {
                goto error;
            }
            state = header_field_start;
            break;
        }
        case header_field_start: { // maybe header field start
            /* we need to determine whether it is a new header or body */
            if (ch == CR) {
                // swallow
                state = headers_done;
                break;
            }
            if (ch == LF) {
                /* they might be just sending \n instead of \r\n so this would be
                 * the second \n to denote the end of headers */
                state = headers_done;
                goto reexec;
            }

            // start parse header
            if (!tokens[data[idx]]) { // unlikely
                // invalid header token error
                goto error;
            }
            // record header info
            left = idx;
            state = header_field;
            // fall through
        }
        case header_field: { // really header field
            // get the end of header field
            int clen;
            hdr_cb = find_header_callback(data + idx, len - idx, sip->settings,
                                          &clen);
            // printf("header: %.*s\n", clen, data + idx);
            idx += clen; // the clen >= 1
            while (idx < len && tokens[data[idx]]) {
                idx++;
            }
            right = idx; // exclude ':'

            if (idx == len) {
                // header field too long
                goto error;
            }
            if (data[idx] == ':') {
                // record header field
                hdr_field.start = (char *)data + left;
                hdr_field.len = right - left;
                // update state
                state = header_value_discard_ws;
                break;
            }
            // TODO: determine header field have any whitespace?

            // error?
            break;
        }
        case header_value_discard_ws: {
            if (data[idx] == ' ' || data[idx] == '\t') break;
            if (ch == CR) {
                // the value is all white space
                state = header_value_discard_ws_almost_done;
                break;
            }

            if (ch == LF) {
                // the value is all white space
                state = header_value_discard_ws_almost_done;
                goto reexec;
            }
            // fall through
        }
        case header_value_start: {
            left = idx;
            state = header_value;
            // fall through
        }
        case header_value: {
            while (idx + 1 < len && data[idx + 1] != CR
                   && data[idx + 1] != LF) {
                idx++;
            }
            if (idx + 1 == len) {
                // header value too long
                goto error;
            }
            right = idx;
            idx++;
            ch = data[idx];
            if (ch == CR) {
                state = header_almost_done;
                break;
            }

            if (ch == LF) {
                state = header_almost_done;
                goto reexec;
            }
            // error?
            goto error;
        }
        case header_value_discard_ws_almost_done: {
            if (tokens[data[idx]] != LF) {
                goto error;
            }
            state = header_value_discard_lws;
            break;
        }
        case header_value_discard_lws: {
            /* header value was empty */
            hdr_value.start = NULL;
            hdr_value.len = 0;
            // TODO: determine header state
            // now we can trigger callback
            global_header_callback(&hdr_field, &hdr_value, hdr_cb,
                                   &sip->headers);
            state = header_field_start;
            break;
        }
        case header_almost_done: {
            if (data[idx] != LF) { // unlikely
                // error
                goto error;
            }
            hdr_value.start = (char *)data + left;
            hdr_value.len = right - left + 1;
            // TODO: determine header state
            // now we can trigger callback
            global_header_callback(&hdr_field, &hdr_value, hdr_cb,
                                   &sip->headers);
            state = header_field_start;
            break;
        }
        case headers_done: {
            if (data[idx] != LF) {
                // error
                goto error;
            }
            printf("headers done\n");
            // determine whether have body
            if (sip->headers.content_length <= 0) {
                state = message_done;
                goto reexec;
            }
            if (len < idx + sip->headers.content_length + 1) {
                // error
                goto error;
            }
            state = body_start;
            break;
        }
        case body_start: {
            sip->body = (char *)data + idx;
            idx += sip->headers.content_length
                 - 1; // reserve same message_done state
            state = message_done;
            // now we can trigger callback
            goto reexec;
        }
        case message_done: { /* last byte of one message */
            // now we can trigger callback
            assert(len == idx + 1);
            break;
        }
        default:
            // error
            break;
        }
    }
    return 0;

error:
    return -1;
}

static inline int add_node(node_t *node, const char *ch, int len, header_cb cb1,
                           header_cb cb2)
{
    node_t *nn = calloc(1, sizeof(node_t));
    if (!nn) {
        return -1;
    }

    nn->ch = ch;
    nn->len = len;
    nn->cb = cb1;
    node->cb = cb2;
    node->childs[*ch - 'a'] = nn;

    return 0;
}

static inline int extend_tree(node_t *node, const char *s2, int len2,
                              header_cb cb2)
{
    const char *s1 = node->ch + 1;
    int len1 = node->len;
    node->len = 0;
    int idx1 = 0, idx2 = 0;
    header_cb cb1 = node->cb;
    node->cb = NULL;
    while (len1 > idx1 && len2 > idx2 && s1[idx1] == s2[idx2]) {
        node_t *nn = calloc(1, sizeof(node_t));
        if (!nn) {
            return -1;
        }
        nn->ch = s1 + idx1;
        nn->len = 0;
        nn->cb = NULL;
        node->childs[s1[idx1] - 'a'] = nn;
        node = nn;

        idx1++;
        idx2++;
    }

    if (len1 > idx1) add_node(node, s1 + idx1, len1 - idx1 - 1, cb1, cb2);
    if (len2 > idx2) add_node(node, s2 + idx2, len2 - idx2 - 1, cb2, cb1);

    return 0;
}

/**
 * Add new callback to the beginning of callback list
 * @return 
 *   0:  add new header callback successfully
 *   1:  update header callback successfully
 *   -1: error
 */
int add_hdr_cb(const char *field, header_cb cb, sip_settings_t *settings)
{
    uint32_t idx = 0, len = strlen(field);
    node_t *pre = &settings->root;
    while (idx < len) {
        int child_idx = tolower(field[idx]) - 'a';
        node_t *node = pre->childs[child_idx];
        if (!node) {
            // 想匹配的节点尚不存在
            if (pre->len > 0) {
                // 当前节点还可以再度扩展
                if (pre->len == (len - idx)
                    && strncmp(pre->ch + 1, field + idx, pre->len) == 0) {
                    // 当前节点与待插入节点完全相同，仅更新callback
                    pre->cb = cb;
                } else {
                    // 延展该节点
                    extend_tree(pre, field + idx, len - idx, cb);
                }
            } else {
                // 当前节点不是叶子节点，新建节点即可
                node_t *nn = calloc(1, sizeof(node_t)); // nn: new node
                if (!nn) {
                    return -1;
                }
                nn->cb = cb;
                nn->ch = field + idx;
                nn->len = len - idx - 1;
                pre->childs[child_idx] = nn;
            }
            break;
        } else {
            pre = node;
        }
        ++idx;
    }

    return 0;
}

static inline void free_nodes(node_t *root)
{
    for (int i = 0; i < MAX_HEADER_LEN; i++) {
        if (root->childs[i]) {
            free_nodes(root->childs[i]);
        }
    }
    free(root);
}

void release_hdr_cbs(sip_settings_t *settings)
{
    for (int i = 0; i < MAX_HEADER_LEN; i++) {
        if (settings->root.childs[i]) {
            free_nodes(settings->root.childs[i]);
        }
    }
}

int set_extra_hdrs(headers_t *headers, void *extra)
{
    if (headers->extra) {
        return 1;
    }
    headers->extra = extra;
    return 0;
}

#define DEF_DEFAULT_HEADER_CB(name)                                           \
  static int default_##name##_cb(str_t *field, str_t *value, headers_t *hdrs) \
  {                                                                           \
    /* todo: Is need to check origin value? */                                \
    (void)field;                                                              \
    hdrs->name.start = value->start;                                          \
    hdrs->name.len = value->len;                                              \
    return 0;                                                                 \
  }

DEF_DEFAULT_HEADER_CB(to)
DEF_DEFAULT_HEADER_CB(from)
DEF_DEFAULT_HEADER_CB(contact)
DEF_DEFAULT_HEADER_CB(p_access_network_info)
DEF_DEFAULT_HEADER_CB(supported)
DEF_DEFAULT_HEADER_CB(allow)
DEF_DEFAULT_HEADER_CB(require)
DEF_DEFAULT_HEADER_CB(proxy_require)
DEF_DEFAULT_HEADER_CB(security_client)
DEF_DEFAULT_HEADER_CB(authorization)
DEF_DEFAULT_HEADER_CB(call_id)
DEF_DEFAULT_HEADER_CB(cseq)
DEF_DEFAULT_HEADER_CB(via)
DEF_DEFAULT_HEADER_CB(user_agent)

#undef DEF_DEFAULT_HEADER_CB

static int default_expires_cb(str_t *field, str_t *value, headers_t *hdrs)
{
    /* The value of this field is an integral number of seconds (in decimal)
       between 0 and (2**32)-1 */
    (void)field;
    int expires = 0;
    for (uint32_t i = 0; i < value->len; i++) {
        if (!isdigit(value->start[i])) {
            return -1;
        }
        expires = expires * 10 + value->start[i] - '0';
    }
    hdrs->expires = expires;
    return 0;
}

static int default_max_forwards_cb(str_t *field, str_t *value, headers_t *hdrs)
{
    /* range 0-255,ref 20.22 */
    (void)field;
    hdrs->max_forwards = atoi(value->start);

    return 0;
}

static int default_content_length_cb(str_t *field, str_t *value,
                                     headers_t *headers)
{
    (void)field;
    headers->content_length = atoi(value->start);

    return 0;
}

int set_default_cbs(sip_settings_t *settings)
{
    if (!settings) {
        return -1;
    }

    int ret = 0;
    // add callback of compact format header
    ret += 0 ^ add_hdr_cb(cpt2long_map['f' - 'a'], default_from_cb, settings);
    ret +=
        0 ^ add_hdr_cb(cpt2long_map['i' - 'a'], default_call_id_cb, settings);
    ret +=
        0 ^ add_hdr_cb(cpt2long_map['k' - 'a'], default_supported_cb, settings);
    ret += 0
         ^ add_hdr_cb(cpt2long_map['l' - 'a'], default_content_length_cb,
                      settings);
    ret +=
        0 ^ add_hdr_cb(cpt2long_map['m' - 'a'], default_contact_cb, settings);
    ret += 0 ^ add_hdr_cb(cpt2long_map['t' - 'a'], default_to_cb, settings);
    ret += 0 ^ add_hdr_cb(cpt2long_map['v' - 'a'], default_via_cb, settings);

    ret += 0 ^ add_hdr_cb("to", default_to_cb, settings);
    ret += 0 ^ add_hdr_cb("from", default_from_cb, settings);
    ret += 0 ^ add_hdr_cb("contact", default_contact_cb, settings);
    ret += 0 ^ add_hdr_cb("expires", default_expires_cb, settings);
    ret += 0
         ^ add_hdr_cb("p-access-network-info", default_p_access_network_info_cb,
                      settings);
    ret += 0 ^ add_hdr_cb("supported", default_supported_cb, settings);
    ret += 0 ^ add_hdr_cb("allow", default_allow_cb, settings);
    ret += 0 ^ add_hdr_cb("require", default_require_cb, settings);
    ret += 0 ^ add_hdr_cb("proxy-require", default_proxy_require_cb, settings);
    ret +=
        0 ^ add_hdr_cb("security-client", default_security_client_cb, settings);
    ret += 0 ^ add_hdr_cb("authorization", default_authorization_cb, settings);
    ret += 0 ^ add_hdr_cb("call-id", default_call_id_cb, settings);
    ret += 0 ^ add_hdr_cb("cseq", default_cseq_cb, settings);
    ret += 0 ^ add_hdr_cb("max-forwards", default_max_forwards_cb, settings);
    ret += 0 ^ add_hdr_cb("via", default_via_cb, settings);
    ret += 0 ^ add_hdr_cb("user-agent", default_user_agent_cb, settings);
    ret +=
        0 ^ add_hdr_cb("content-length", default_content_length_cb, settings);
    return ret;
}

#define DUMP_HEADER_STR(name) \
  printf("%s: %.*s\n", #name, sip->headers.name.len, sip->headers.name.start);
#define DUMP_HEADER_NUM(name) printf("%s: %d\n", #name, sip->headers.name);

void dump_sip(sip_t *sip)
{
    if (sip->type == SIP_REQUEST) {
        printf("%s %.*s SIP/%u.%u\n", method_strings[sip->req.method],
               sip->req.uri.len, sip->req.uri.start, sip->major, sip->minor);
    } else if (sip->type == SIP_RESPONSE) {
        printf("SIP/%u.%u %d %.*s\n", sip->major, sip->minor,
               sip->res.status_code, sip->res.status.len,
               sip->res.status.start);
    } else {
        printf("unknown sip type\n");
    }
    /* dump headers */
    DUMP_HEADER_STR(to)
    DUMP_HEADER_STR(from)
    DUMP_HEADER_STR(contact)
    DUMP_HEADER_NUM(expires)
    DUMP_HEADER_STR(p_access_network_info)
    DUMP_HEADER_STR(supported)
    DUMP_HEADER_STR(allow)
    DUMP_HEADER_STR(require)
    DUMP_HEADER_STR(proxy_require)
    DUMP_HEADER_STR(security_client)
    DUMP_HEADER_STR(authorization)
    DUMP_HEADER_STR(call_id)
    DUMP_HEADER_STR(cseq)
    DUMP_HEADER_NUM(max_forwards)
    DUMP_HEADER_STR(via)
    DUMP_HEADER_STR(user_agent)
    DUMP_HEADER_NUM(content_length)
    /* dump body */
    if (sip->headers.content_length > 0) {
        printf("%.*s\n", sip->headers.content_length, sip->body);
    }
}
#undef DUMP_HEADER_STR
#undef DUMP_HEADER_NUM
