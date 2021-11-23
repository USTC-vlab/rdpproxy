#include <iostream>
#include <thread>
#include <cstring>
#include <xkbcommon/xkbcommon.h>
#include "util.h"
#include "session.h"
#include "config.h"
#include "auth.h"
#include "font.h"
#include "key.h"

using namespace std;
using boost::asio::ip::tcp;

static const tuple<bool, bool, string, ssize_t> HandshakeError(false, false, "", 0);

extern Configuration configuration;

Session::Session(boost::asio::io_context &ioc_, tcp::socket &socket)
    : ioc(ioc_), downstream_socket(move(socket)), upstream_socket(ioc), has_closed(false) {
    downstream_socket.set_option(tcp::no_delay(true));
    downstream_socket.set_option(boost::asio::socket_base::keep_alive(true));
    ip = downstream_socket.remote_endpoint().address().to_string();
}

void Session::start() {
    boost::asio::co_spawn(ioc.get_executor(),
        [self = shared_from_this()] {
            return self->handle();
        }, boost::asio::detached
    );
}

void Session::close() {
    if (has_closed) {
        return;
    }
    if (downstream_socket.is_open()) {
        boost::system::error_code ec;
        downstream_socket.shutdown(tcp::socket::shutdown_both, ec);
        downstream_socket.close();
    }
    if (upstream_socket.is_open()) {
        boost::system::error_code ec;
        upstream_socket.shutdown(tcp::socket::shutdown_both, ec);
        upstream_socket.close();
    }
    has_closed = true;
}

boost::asio::awaitable<void> Session::handle() {
    try {
        bool success, is_redirection;
        vector<uint8_t> cr_pdu;
        string token;
        size_t neg_offset;
        tie(success, is_redirection, token, neg_offset) = co_await handshake(cr_pdu);
        if (!success) {
            close();
            co_return;
        }
        if (is_redirection) {
            string username;
            string ip;
            uint16_t port;
            if (!co_await auth(token, username, ip, port, ioc)) {
                close();
                co_return;
            }
            co_await upstream_socket.async_connect(
                tcp::endpoint(boost::asio::ip::address::from_string(ip), port),
                boost::asio::use_awaitable);
            upstream_socket.set_option(tcp::no_delay(true));
            //co_await ASYNC_WRITE(upstream_socket, cr_pdu);
            boost::asio::co_spawn(ioc.get_executor(),
                [self = shared_from_this(), this] {
                    return handle_up_to_down();
                }, boost::asio::detached
            );
            boost::asio::co_spawn(ioc.get_executor(),
                [self = shared_from_this(), this] {
                    return handle_down_to_up();
                }, boost::asio::detached
            );
        } else {
            rdp.reset(new RDPSession(downstream_socket.native_handle(), ioc));
            if (rdp->init()) {
                std::thread rdp_thread([self = shared_from_this(), this] {
                    rdp->run(self);
                });
                rdp_thread.detach();
            }
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}

boost::asio::awaitable<Session::HandshakeResult> Session::handshake(vector<uint8_t> &cr_pdu) {
    string cookie;
    vector<uint8_t> buffer;
    ssize_t neg_offset;
    if (!co_await peak_x224_cr_pdu(cookie, buffer, neg_offset)) {
        co_return HandshakeError;
    }
    bool is_redirection = false;
    string token;
    string prefix("Cookie: msts=");
    if (str_startswith(cookie, prefix)) {
        is_redirection = true;
        size_t old_size = buffer.size();
        size_t cookie_size = cookie.size() + 2;
        cr_pdu.resize(old_size - cookie_size);
        uint8_t *p = cr_pdu.data();
        memcpy(p, buffer.data(), 11);
        ssize_t remain_size = old_size - 11 - cookie_size;
        if (remain_size > 0) {
            memcpy(cr_pdu.data() + 11, buffer.data() + 11 + cookie_size, remain_size);
        }
        store_u16be(p + 2, old_size - cookie_size);
        p[4] = old_size - cookie_size - 5;
        token = cookie.substr(prefix.length());
        neg_offset -= cookie_size;
    } else {
        cr_pdu = std::move(buffer);
    }
    co_return HandshakeResult(true, is_redirection, token, neg_offset);
}

boost::asio::awaitable<bool> Session::read_x224_cr_pdu(string &cookie, vector<uint8_t> &buffer, ssize_t &neg_offset) {
    uint8_t tpkt_version = co_await read_u16(downstream_socket, buffer);
    if (tpkt_version != 0x03) {
        co_return false;
    }
    size_t tpkt_size = co_await read_u16be(downstream_socket, buffer);
    uint8_t length_indicator = co_await read_u8(downstream_socket, buffer);
    if (tpkt_size != length_indicator + 5) {
        co_return false;
    }
    uint8_t cr_cdt = co_await read_u8(downstream_socket, buffer);
    if (cr_cdt != 0xe0) {
        co_return false;
    }
    uint16_t dst_ref = co_await read_u16(downstream_socket, buffer);
    if (dst_ref != 0) {
        co_return false;
    }
    uint16_t src_ref = co_await read_u16(downstream_socket, buffer);
    uint8_t class_option = co_await read_u8(downstream_socket, buffer);
    if ((class_option & 0xfc) != 0) {
        co_return false;
    }
    size_t size = length_indicator - 6;
    uint8_t *p = co_await read_bytes(downstream_socket, buffer, size);
    size_t pos = search_crlf(p, size);
    if (pos != string::npos) {
        cookie = string((const char *)p, pos);
        neg_offset = p - buffer.data() + pos + 2;
    } else {
        neg_offset = p - buffer.data();
    }
    co_return true;
}

boost::asio::awaitable<bool> Session::peak_x224_cr_pdu(std::string &cookie, std::vector<uint8_t> &buffer, ssize_t &neg_offset) {
    uint8_t *p = co_await peek_bytes(downstream_socket, buffer, 4);
    uint8_t tpkt_version = p[0];
    if (tpkt_version != 0x03) {
        co_return false;
    }
    uint16_t tpkt_size = load_u16be(p + 2);
    p = co_await peek_bytes(downstream_socket, buffer, tpkt_size);
    uint8_t length_indicator = p[4];
    uint8_t cr_cdt = p[5];
    uint16_t dst_ref = load_u16(p + 6);
    uint16_t src_ref = load_u16(p + 8);
    uint8_t class_option = p[10];
    if (tpkt_size - 5 != length_indicator || cr_cdt != 0xe0 || dst_ref != 0 || (class_option & 0xfc) != 0) {
        co_return false;
    }
    p += 11;
    size_t pos = search_crlf(p, buffer.size() - 11);
    if (pos != string::npos) {
        cookie = string((const char *)p, pos);
        neg_offset = p - buffer.data() + pos + 2;
    } else {
        neg_offset = p - buffer.data();
    }
    co_return true;
}

boost::asio::awaitable<void> Session::handle_up_to_down() {
    const size_t BufferSize = 65536;
    vector<uint8_t> buffer(BufferSize);
    try {
        while (true) {
            size_t size = co_await ASYNC_READ_SOME(upstream_socket, buffer, BufferSize);
            co_await ASYNC_WRITE(downstream_socket, buffer, size);
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}

boost::asio::awaitable<void> Session::handle_down_to_up() {
    const size_t BufferSize = 65536;
    vector<uint8_t> buffer(BufferSize);
    try {
        while (true) {
            size_t size = co_await ASYNC_READ_SOME(downstream_socket, buffer, BufferSize);
            co_await ASYNC_WRITE(upstream_socket, buffer, size);
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}

RDPSession::RDPSession(int fd_, boost::asio::io_context &ioc_) : fd(fd_), peer(nullptr),
    context(nullptr), rfx(nullptr), nsc(nullptr), stream(nullptr), has_activated(false),
    screen_width(640), screen_height(384), frame_id(0), vt(nullptr),
    default_fg_color(0x00f8f8f2), default_bg_color(0x00272822), in_pipe_fd {-1,-1}, out_pipe_fd {-1,-1},
    xkb_context_(nullptr), xkb_keymap_(nullptr), xkb_state_(nullptr), ioc(ioc_) {}

RDPSession::~RDPSession() {
    if (peer) {
        freerdp_peer_context_free(peer);
        freerdp_peer_free(peer);
    }
    if (xkb_state_) {
        xkb_state_unref(xkb_state_);
    }
    if (xkb_keymap_) {
        xkb_keymap_unref(xkb_keymap_);
    }
    if (xkb_context_) {
        xkb_context_unref(xkb_context_);
    }
}

BOOL RDPSession::rdp_context_new(freerdp_peer *peer_, rdpContext *ctx) {
    RDPSession* session = (RDPSession *)peer_->ContextExtra;
    session->context = ctx;
    return session->context_new();
}

void RDPSession::rdp_context_free(freerdp_peer *peer_, rdpContext *ctx) {
    RDPSession* session = (RDPSession *)peer_->ContextExtra;
    session->context_free();
}

BOOL RDPSession::rdp_post_connect(freerdp_peer* peer_) {
    RDPSession* session = (RDPSession *)peer_->ContextExtra;
    return session->post_connect();
}

BOOL RDPSession::rdp_activate(freerdp_peer* peer_) {
    RDPSession* session = (RDPSession *)peer_->ContextExtra;
    return session->activate();
}

BOOL RDPSession::rdp_keyboard_event(rdpInput* input, UINT16 flags, UINT16 code) {
    RDPSession* session = ((RDPContext *)input->context)->session;
    return session->keyboard_event(flags, code);
}

BOOL RDPSession::rdp_refresh_rect(rdpContext* context, BYTE count, const RECTANGLE_16* areas) {
    RDPSession* session = ((RDPContext *)context)->session;
    return session->refresh_rect(count, areas);
}

void RDPSession::terminal_output_callback(const char *s, size_t len, void *user) {
    RDPSession *session = (RDPSession *)user;
    session->terminal_output(s, len);
}

int RDPSession::screen_damage(VTermRect rect, void *user) {
    RDPSession *session = (RDPSession *)user;
    session->damage(rect);
    return 1;
}

int RDPSession::screen_move_cursor(VTermPos pos, VTermPos oldpos, int visible, void *user) {
    RDPSession *session = (RDPSession *)user;
    session->move_cursor(pos, oldpos, visible);
    return 1;
}

bool RDPSession::post_connect() {
    if (peer->settings->AutoLogonEnabled) {
        username = peer->settings->Username;
        password = peer->settings->Password;
    }
    if (!rfx_context_reset(rfx, screen_width, screen_height)) {
        return false;
    }
    peer->settings->DesktopWidth = rfx->width;
    peer->settings->DesktopHeight = rfx->height;
    peer->update->DesktopResize(context);
    framebuffer.resize(screen_width * screen_height);
    return true;
}

bool RDPSession::activate() {
    peer->settings->CompressionLevel = PACKET_COMPR_TYPE_RDP61;
    for (int i = 0; i < screen_height; ++i) {
        for (int j = 0; j < screen_width; ++j) {
            framebuffer[i * screen_width + j] = default_bg_color;
        }
    }
    has_activated = true;
    draw_rect(0, 0, screen_width, screen_height);
    return true;
}

bool RDPSession::keyboard_event(uint16_t flags, uint16_t code) {
    if (!has_activated) {
        return true;
    }
    bool down = flags & KBD_FLAGS_RELEASE;
    uint32_t keycode = code + 8;
    uint32_t keysym = xkb_state_key_get_one_sym(xkb_state_, keycode);
    xkb_state_update_key(xkb_state_, keycode, down ? XKB_KEY_UP : XKB_KEY_DOWN);
    if (down) {
        pressed_keys.insert(code);
    } else {
        pressed_keys.erase(code);
    }
    if (down) {
        if (keysym == XKB_KEY_Shift_L || keysym == XKB_KEY_Shift_R ||
            keysym == XKB_KEY_Alt_L || keysym == XKB_KEY_Alt_R ||
            keysym == XKB_KEY_Control_L || keysym == XKB_KEY_Control_R) {
          return true;
        }
        int mod = VTERM_MOD_NONE;
        if (pressed_keys.count(XKB_KEY_Shift_L) || pressed_keys.count(XKB_KEY_Shift_R)) {
            mod |= VTERM_MOD_SHIFT;
        }
        if (pressed_keys.count(XKB_KEY_Alt_L) || pressed_keys.count(XKB_KEY_Alt_R)) {
            mod |= VTERM_MOD_ALT;
        }
        if (pressed_keys.count(XKB_KEY_Control_L) || pressed_keys.count(XKB_KEY_Control_R)) {
            mod |= VTERM_MOD_CTRL;
        }
        auto it = KeysymVTermKeyMap.find(keysym);
        if (it != KeysymVTermKeyMap.end()) {
            vterm_keyboard_key(vt, (VTermKey)it->second, (VTermModifier)mod);
        } else {
            uint32_t ch = xkb_state_key_get_utf32(xkb_state_, keycode);
            if (ch != '\t') {
                vterm_keyboard_unichar(vt, ch, (VTermModifier)mod);
            }
        }
    }
    return true;
}

bool RDPSession::refresh_rect(BYTE count, const RECTANGLE_16* areas) {
    for (int i = 0; i < count; ++i) {
        int x1 = areas[i].left;
        int y1 = areas[i].top;
        int x2 = areas[i].right;
        int y2 = areas[i].bottom;
        if (x1 < 0 || y1 < 0 || x2 <= x1 || y2 <= y1 || x2 >= screen_width || y2 >= screen_height) {
            continue;
        }
        int w = x2 - x1;
        int h = y2 - y1;
        draw_rect(x1, y1, w, h);
    }
    return true;
}

bool RDPSession::draw_rect(int x, int y, int w, int h) {
    if (!has_activated) {
        return true;
    }
    if (!peer->settings->RemoteFxCodec && !peer->settings->NSCodec) {
        return false;
    }
    Stream_Clear(stream);
    Stream_SetPosition(stream, 0);
    RFX_RECT rect;
    rdpUpdate* update = peer->update;
    SURFACE_BITS_COMMAND cmd = { 0 };
    rect.x = 0;
    rect.y = 0;
    rect.width = w;
    rect.height = h;
    if (peer->settings->RemoteFxCodec) {
        if (!rfx_compose_message(rfx, stream, &rect, 1,
            (uint8_t *)(framebuffer.data() + y * screen_width + x), w, h, screen_width * 4)) {
            return false;
        }
        cmd.bmp.codecID = peer->settings->RemoteFxCodecId;
        cmd.cmdType = CMDTYPE_STREAM_SURFACE_BITS;
    } else {
        nsc_compose_message(nsc, stream,
            (uint8_t *)(framebuffer.data() + y * screen_width + x), w, h, screen_width * 4);
        cmd.bmp.codecID = peer->settings->NSCodecId;
        cmd.cmdType = CMDTYPE_SET_SURFACE_BITS;
    }
    cmd.destLeft = x;
    cmd.destTop = y;
    cmd.destRight = x + w;
    cmd.destBottom = y + h;
    cmd.bmp.bpp = 32;
    cmd.bmp.flags = 0;
    cmd.bmp.width = w;
    cmd.bmp.height = h;
    cmd.bmp.bitmapDataLength = Stream_GetPosition(stream);
    cmd.bmp.bitmapData = Stream_Buffer(stream);
    begin_frame();
    update->SurfaceBits(update->context, &cmd);
    end_frame();
    return true;
}

void RDPSession::begin_frame() {
    rdpUpdate* update = peer->update;
    SURFACE_FRAME_MARKER fm = { 0 };
    fm.frameAction = SURFACECMD_FRAMEACTION_BEGIN;
    fm.frameId = frame_id;
    update->SurfaceFrameMarker(update->context, &fm);
}

void RDPSession::end_frame() {
    rdpUpdate* update = peer->update;
    SURFACE_FRAME_MARKER fm = { 0 };
    fm.frameAction = SURFACECMD_FRAMEACTION_END;
    fm.frameId = frame_id;
    update->SurfaceFrameMarker(update->context, &fm);
    ++frame_id;
}

void RDPSession::damage(VTermRect rect) {
    int x1 = rect.start_col;
    int x2 = rect.end_col;
    int y1 = rect.start_row;
    int y2 = rect.end_row;
    if (x1 >= x2 || y1 >= y2) {
        return;
    }
    if (x1 < 0 || x2 > cols || y1 < 0 || y2 > lines) {
        return;
    }
    for (int i = y1; i < y2; ++i) {
        for (int j = x1; j < x2; ++j) {
            VTermPos pos {i, j};
            render_cell(pos);
        }
    }
}

void RDPSession::move_cursor(VTermPos pos, VTermPos oldpos, bool visible) {
    if (pos.row < 0 || pos.row >= lines || pos.col < 0 || pos.col >= cols) {
        return;
    }
    if (visible) {
        render_cursor(pos);
    }
    if (oldpos.row < 0 || oldpos.row >= lines || oldpos.col < 0 || oldpos.col >= cols) {
        return;
    }
    render_cell(oldpos);
}

void RDPSession::render_cursor(VTermPos pos) {
    VTermScreenCell cell;
    if (!vterm_screen_get_cell(vt_screen, pos, &cell)) {
        return;
    }
    int x = pos.col;
    int y = pos.row;
    uint32_t ch = cell.chars[0];
    if (ch == (uint32_t)(-1)) {
        render_glyph(x, y, 1, 0, default_bg_color, default_fg_color);
    } else {
        render_cell(pos, true);
    }
}

void RDPSession::render_cell(VTermPos pos, bool reverse) {
    VTermScreenCell cell;
    if (!vterm_screen_get_cell(vt_screen, pos, &cell)) {
        return;
    }
    uint32_t ch = cell.chars[0];
    if (ch == (uint32_t)(-1)) {
        return;
    }
    int x = pos.col;
    int y = pos.row;
    if (x < 0 || x >= cols || y < 0 || y >= lines) {
        return;
    }
    int width = cell.width;
    uint32_t fg = default_fg_color;
    uint32_t bg = default_bg_color;
    VTermColor fgc = cell.fg;
    VTermColor bgc = cell.bg;
    if (!VTERM_COLOR_IS_DEFAULT_FG(&fgc)) {
      vterm_state_convert_color_to_rgb(vt_state, &fgc);
      fg = (fgc.rgb.red << 16) | (fgc.rgb.green << 8) | fgc.rgb.blue;
    }
    if (!VTERM_COLOR_IS_DEFAULT_BG(&bgc)) {
      vterm_state_convert_color_to_rgb(vt_state, &bgc);
      bg = (bgc.rgb.red << 16) | (bgc.rgb.green << 8) | fgc.rgb.blue;
    }
    if (reverse) {
      swap(fg, bg);
    }
    render_glyph(x, y, width, ch, fg, bg);
}

void RDPSession::terminal_output(const char *s, size_t len) {
    if (in_pipe_fd[1] != -1) {
        write(in_pipe_fd[1], s, len);
    }
}

void RDPSession::render_glyph(int x, int y, int width, uint32_t ch, uint32_t fg, uint32_t bg) {
    if (!has_activated) {
        return;
    }
    if (width > 2) {
        width = 2;
    }
    if (x == cols - 1) {
        width = 1;
    }
    int stride = screen_width;
    int padx = (screen_width - cols * GlyphWidth / 2) / 2;
    int pady = (screen_height - lines * GlyphHeight) / 2;
    int x1 = padx + GlyphWidth / 2 * x;
    int y1 = pady + GlyphHeight * y;
    int x2 = x1 + GlyphWidth * width / 2;
    int y2 = y1 + GlyphHeight;
    uint32_t *buffer = framebuffer.data() + y1 * stride + x1;
    size_t glyph_index = ch < GlyphBitmapSize ? ch : 0;
    if (ch == 0) {
        for (int i = 0; i < GlyphHeight; ++i) {
            int gw = width == 2 ? GlyphWidth : GlyphWidth / 2;
            for (int j = 0; j < gw; ++j) {
                buffer[i * stride + j] = bg;
            }
        }
    } else {
        for (int i = 0; i < GlyphHeight; ++i) {
            uint16_t line = GlyphBitmap[glyph_index][i];
            int gw = width == 2 ? GlyphWidth : GlyphWidth / 2;
            for (int j = 0; j < gw; ++j) {
                if (line & (1 << j)) {
                    buffer[i * stride + j] = fg;
                } else {
                    buffer[i * stride + j] = bg;
                }
            }
        }
    }
    if (has_activated) {
        draw_rect(x1, y1, x2 - x1, y2 - y1);
    }
}

bool RDPSession::init() {
    peer = freerdp_peer_new(fd);
    if (!peer) {
        return true;
    }
    peer->ContextSize = sizeof(RDPContext);
    peer->ContextExtra = this;
    peer->ContextNew = rdp_context_new;
    peer->ContextFree = rdp_context_free;
    if (!freerdp_peer_context_new(peer)) {
        return false;
    }
    peer->settings->CertificateFile = strdup(configuration.cert_chain_file.c_str());
    peer->settings->PrivateKeyFile = strdup(configuration.private_key_file.c_str());
    peer->settings->RdpSecurity = false;
    peer->settings->TlsSecurity = true;
    peer->settings->NlaSecurity = false;
    peer->settings->EncryptionLevel = ENCRYPTION_LEVEL_CLIENT_COMPATIBLE;
    peer->settings->RemoteFxCodec = true;
    peer->settings->NSCodec = true;
    peer->settings->ColorDepth = 32;
    peer->settings->SuppressOutput = true;
    peer->settings->RefreshRect = true;
    peer->PostConnect = rdp_post_connect;
    peer->Activate = rdp_activate;
    peer->input->KeyboardEvent = rdp_keyboard_event;
    peer->update->RefreshRect = rdp_refresh_rect;
    peer->Initialize(peer);

    // init terminal
    lines = screen_height / GlyphHeight;
    cols = screen_width / (GlyphWidth / 2);
    vt = vterm_new(lines, cols);
    if (!vt) {
        return false;
    }
    vterm_set_utf8(vt, 1);
    vt_screen = vterm_obtain_screen(vt);
    vt_state = vterm_obtain_state(vt);
    vterm_screen_reset(vt_screen, 1);
    vterm_state_reset(vt_state, 1);
    memset(&screen_callbacks, 0, sizeof(VTermScreenCallbacks));
    screen_callbacks.damage = screen_damage;
    screen_callbacks.movecursor = screen_move_cursor;
    vterm_screen_set_callbacks(vt_screen, &screen_callbacks, this);
    vterm_output_set_callback(vt, terminal_output_callback, this);
    VTermColor fg, bg;
    vterm_color_rgb(&fg, (default_fg_color & 0xff000000) >> 24,
        (default_fg_color & 0xff0000) >> 16, (default_fg_color & 0xff00) >> 8);
    vterm_color_rgb(&bg, (default_bg_color & 0xff000000) >> 24,
        (default_bg_color & 0xff0000) >> 16, (default_bg_color & 0xff00) >> 8);
    vterm_state_set_default_colors(vt_state, &fg, &bg);
    if (pipe(in_pipe_fd) < 0 || pipe(out_pipe_fd) < 0) {
        return false;
    }
    xkb_context_ = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
    if (!xkb_context_) {
        return false;
    }
    xkb_keymap_ = xkb_keymap_new_from_names(xkb_context_, nullptr, XKB_KEYMAP_COMPILE_NO_FLAGS);
    if (!xkb_keymap_) {
        return false;
    }
    xkb_state_ = xkb_state_new(xkb_keymap_);
    if (!xkb_state_) {
        return false;
    }
    return true;
}

bool RDPSession::context_new() {
    ((RDPContext *)context)->session = this;
    rfx = rfx_context_new(true);
    if (!rfx) {
        return false;
    }
    if (!rfx_context_reset(rfx, screen_width, screen_height)) {
        return false;
    }
    rfx->mode = RLGR3;
    rfx_context_set_pixel_format(rfx, PIXEL_FORMAT_BGRA32);
    nsc = nsc_context_new();
    if (!nsc) {
        return false;
    }
    if (!nsc_context_set_parameters(nsc, NSC_COLOR_FORMAT, PIXEL_FORMAT_BGRA32)) {
        return false;
    }
    stream = Stream_New(nullptr, 65536);
    if (!stream) {
        return false;
    }
    return true;
}

void RDPSession::context_free() {
    if (context) {
        Stream_Free(stream, true);
        rfx_context_free(rfx);
        nsc_context_free(nsc);
    }
}

void RDPSession::run(std::shared_ptr<Session> session) {
    HANDLE handles[32];
    DWORD numHandles;
    char buffer[2048];
    fcntl(out_pipe_fd[0], F_SETFL, fcntl(out_pipe_fd[0], F_GETFL, 0) | O_NONBLOCK);
    bool has_started_greeter = false;
    while (true) {
        if (has_activated && !has_started_greeter) {
            boost::asio::co_spawn(ioc.get_executor(),
                [session, this] {
                    return greeter();
                }, boost::asio::detached
            );
            has_started_greeter = true;
        }
        numHandles = peer->GetEventHandles(peer, handles, 30);
        handles[numHandles++] = CreateFileDescriptorEvent(NULL, FALSE, FALSE, out_pipe_fd[0], WINPR_FD_READ);
        if (numHandles == 0) {
          break;
        }
        if (WaitForMultipleObjects(numHandles, handles, false, 10000) == WAIT_FAILED) {
          break;
        }
        if (!peer->CheckFileDescriptor(peer)) {
          break;
        }
        if (has_activated) {
            ssize_t len = read(out_pipe_fd[0], buffer, sizeof(buffer));
            if (len > 0 && vt) {
                vterm_input_write(vt, buffer, len);
            }
        }
    }
    peer->Disconnect(peer);
}

static boost::asio::awaitable<bool> read_line(
    boost::asio::posix::stream_descriptor &in,
    boost::asio::posix::stream_descriptor &out,
    const string &prompt, string &line, bool visible = true
) {
    co_await ASYNC_WRITE(out, prompt);
    char ch;
    char mask = '*';
    size_t cursor = line.length();
    string csi_command;
    while (true) {
        if (co_await ASYNC_READ(in, &ch, 1) <= 0) {
            co_return false;
        }
        if (ch == '\r' || ch == '\n') {
            break;
        } else if (ch == '\b' || ch == 127) {
            if (cursor == line.length()) {
                if (!line.empty()) {
                    --cursor;
                    if (co_await ASYNC_WRITE(out, "\e[D \e[D", 7) <= 0) {
                        co_return false;
                    }
                    line = line.substr(0, line.length() - 1);
                }
            } else if (cursor > 0) {
                const string& s1 = line.substr(0, cursor - 1);
                const string& s2 = line.substr(cursor);
                --cursor;
                line = s1 + s2;
                string echo = "\e[D\e[K";
                if (visible) {
                    echo += s2;
                } else {
                    echo.resize(echo.length() + s2.length(), mask);
                }
                echo += "\e[" + to_string(s2.length()) + "D";
                if (co_await ASYNC_WRITE(out, echo) <= 0) {
                    co_return false;
                }
            }
        } else if (ch == '\e') {
            csi_command = ch;
            while (true) {
                if (co_await ASYNC_READ(in, &ch, 1) <= 0) {
                    co_return false;
                }
                csi_command += ch;
                if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
                    break;
                }
                switch (ch) {
                case '@':
                case '[':
                case '\\':
                case ']':
                case '^':
                case '_':
                case '`':
                case '{':
                case '|':
                case '}':
                case '~':
                    break;
                }
            }
            if (csi_command == "\e[D" && cursor >= 1) {
                if (co_await ASYNC_WRITE(out, csi_command) <= 0) {
                    co_return false;
                }
                --cursor;
            } else if (csi_command == "\e[C" && cursor < line.length()) {
                if (co_await ASYNC_WRITE(out, csi_command) <= 0) {
                    co_return false;
                }
                ++cursor;
            }
        } else {
            if (cursor == line.length()) {
                line += ch;
                ++cursor;
                if (co_await ASYNC_WRITE(out, visible ? &ch : &mask, 1) <= 0) {
                    co_return false;
                }
            } else {
                const string& s1 = line.substr(0, cursor);
                const string& s2 = line.substr(cursor);
                line = s1 + ch + s2;
                string echo;
                ++cursor;
                if (visible) {
                    echo = ch + s2;
                } else {
                    echo.resize(s2.length() + 1, mask);
                }
                echo += "\e[" + to_string(s2.length()) + "D";
                if (co_await ASYNC_WRITE(out, echo) <= 0) {
                    co_return false;
                }
            }
        }
    }
    co_return true;
}

boost::asio::awaitable<void> RDPSession::greeter() {
    boost::asio::posix::stream_descriptor in(ioc, in_pipe_fd[0]);
    boost::asio::posix::stream_descriptor out(ioc, out_pipe_fd[1]);
    string str_banner =
    "欢迎使用Vlab。请输入学号或工号及密码以登录系统。\r\n"
    "请注意为学号或工号和密码，而非Linux或Windows系统的用户名密码！\r\n"
    "登录成功后还需要系统的用户名密码\r\n";
    string str_username = "学号或工号: ";
    string str_password = "\r\n密码: ";
    string str_invisible = "*";
    string str_wait = "\r\n登录中，请稍候…\r\n";
    string str_failed = "登录失败！请重试。\r\n";
    co_await ASYNC_WRITE(out, str_banner);
    const int maxRetryTimes = 5;
    for (int i = 0; i < maxRetryTimes; ++i) {
        if (username.empty() || password.empty()) {
            if (!co_await read_line(in, out, str_username, username) ||
                !co_await read_line(in, out, str_password, password, false)) {
                co_return;
            }
        }
    
        if (co_await ASYNC_WRITE(out, str_wait) <= 0) {
            co_return;
        }
        co_return;
    }
    co_return;
}