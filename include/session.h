#pragma once
#include <memory>
#include <string>
#include <tuple>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <ctime>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

#include <winpr/crt.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <winpr/file.h>
#include <winpr/string.h>
#include <winpr/path.h>
#include <winpr/winsock.h>

#include <freerdp/channels/wtsvc.h>
#include <freerdp/channels/channels.h>

#include <freerdp/constants.h>
#include <freerdp/server/rdpsnd.h>
#include <vterm.h>
#include <xkbcommon/xkbcommon.h>

class RDPSession;
class Session: public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::io_context &ioc_, boost::asio::ip::tcp::socket &socket);
    void start();
    void close();
private:
    using HandshakeResult = std::tuple<bool, bool, std::string, ssize_t>; // success, redirection, token, neg_req_offset
    boost::asio::awaitable<void> handle();
    boost::asio::awaitable<HandshakeResult> handshake(std::vector<uint8_t> &cr_pdu);
    boost::asio::awaitable<bool> read_x224_cr_pdu(std::string &cookie, std::vector<uint8_t> &buffer, ssize_t &neg_offset);
    boost::asio::awaitable<bool> peak_x224_cr_pdu(std::string &cookie, std::vector<uint8_t> &buffer, ssize_t &neg_offset);
    boost::asio::awaitable<void> handle_up_to_down();
    boost::asio::awaitable<void> handle_down_to_up();
    boost::asio::io_context &ioc;
    boost::asio::ip::tcp::socket upstream_socket;
    boost::asio::ip::tcp::socket downstream_socket;
    std::unique_ptr<RDPSession> rdp;
    std::string ip;
    bool has_closed;
};

class RDPSession {
public:
    RDPSession(int fd, boost::asio::io_context &ioc_);
    ~RDPSession();
    bool init();
    void run(std::shared_ptr<Session> session);
private:
    static BOOL rdp_context_new(freerdp_peer *peer_, rdpContext *ctx);
    static void rdp_context_free(freerdp_peer *peer_, rdpContext *ctx);
    static BOOL rdp_post_connect(freerdp_peer* peer_);
    static BOOL rdp_activate(freerdp_peer* peer_);
    static BOOL rdp_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code);
    static BOOL rdp_refresh_rect(rdpContext* context, BYTE count, const RECTANGLE_16* areas);
    static void terminal_output_callback(const char *s, size_t len, void *user);
    static int screen_damage(VTermRect rect, void *user);
    static int screen_move_cursor(VTermPos pos, VTermPos oldpos, int visible, void *user);
    bool context_new();
    void context_free();
    bool post_connect();
    bool activate();
    bool keyboard_event(uint16_t flags, uint16_t code);
    bool refresh_rect(BYTE count, const RECTANGLE_16* areas);
    bool draw_rect(int x, int y, int w, int h);
    void begin_frame();
    void end_frame();
    void damage(VTermRect rect);
    void move_cursor(VTermPos pos, VTermPos oldpos, bool visible);
    void render_cursor(VTermPos pos);
    void render_cell(VTermPos pos, bool reverse = false);
    void terminal_output(const char *s, size_t len);
    void render_glyph(int x, int y, int width, uint32_t ch, uint32_t fg, uint32_t bg);
    void redirect();
    boost::asio::awaitable<void> greeter();

    int fd;
    freerdp_peer *peer;
    rdpContext *context;
    RFX_CONTEXT *rfx;
    NSC_CONTEXT *nsc;
    wStream *stream;
    bool has_activated;
    std::string token;
    std::string username;
    std::string password;
    std::string ip;
    std::string host_username;
    std::vector<uint32_t> framebuffer;
    int screen_width;
    int screen_height;
    int frame_id;
    VTerm *vt;
    VTermScreen *vt_screen;
    VTermState *vt_state;
    VTermScreenCallbacks screen_callbacks;
    VTermStateCallbacks state_callbacks;
    int lines;
    int cols;
    int in_pipe_fd[2];
    int out_pipe_fd[2];
    int requested_width;
    int requested_height;
    int default_fg_color;
    int default_bg_color;
    xkb_context *xkb_context_;
    xkb_keymap *xkb_keymap_;
    xkb_state *xkb_state_;
    std::unordered_set<uint32_t> pressed_keys;
    bool has_authenticated;
    bool has_redirected;
    bool has_denied;
    boost::asio::io_context &ioc;
};

struct RDPContext {
    rdpContext context;
    RDPSession *session;
};