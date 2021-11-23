#pragma once
#include <xkbcommon/xkbcommon.h>
#include <freerdp/scancode.h>
#include <vterm.h>

static const std::unordered_map<uint32_t, int> KeysymVTermKeyMap = {
  {XKB_KEY_Return,        VTERM_KEY_ENTER},
//  {XKB_KEY_Tab,           VTERM_KEY_TAB},
  {XKB_KEY_BackSpace,     VTERM_KEY_BACKSPACE},
  {XKB_KEY_Escape,        VTERM_KEY_ESCAPE},

  {XKB_KEY_Up,            VTERM_KEY_UP},
  {XKB_KEY_Down,          VTERM_KEY_DOWN},
  {XKB_KEY_Left,          VTERM_KEY_LEFT},
  {XKB_KEY_Right,         VTERM_KEY_RIGHT},

  {XKB_KEY_Insert,        VTERM_KEY_INS},
  {XKB_KEY_Delete,        VTERM_KEY_DEL},
  {XKB_KEY_Home,          VTERM_KEY_HOME},
  {XKB_KEY_End,           VTERM_KEY_END},
  {XKB_KEY_Page_Up,       VTERM_KEY_PAGEUP},
  {XKB_KEY_Page_Down,     VTERM_KEY_PAGEDOWN},

  {XKB_KEY_F1,            VTERM_KEY_FUNCTION_0 + 1},
  {XKB_KEY_F2,            VTERM_KEY_FUNCTION_0 + 2},
  {XKB_KEY_F3,            VTERM_KEY_FUNCTION_0 + 3},
  {XKB_KEY_F4,            VTERM_KEY_FUNCTION_0 + 4},
  {XKB_KEY_F5,            VTERM_KEY_FUNCTION_0 + 5},
  {XKB_KEY_F6,            VTERM_KEY_FUNCTION_0 + 6},
  {XKB_KEY_F7,            VTERM_KEY_FUNCTION_0 + 7},
  {XKB_KEY_F8,            VTERM_KEY_FUNCTION_0 + 8},
  {XKB_KEY_F9,            VTERM_KEY_FUNCTION_0 + 9},
  {XKB_KEY_F10,           VTERM_KEY_FUNCTION_0 + 10},
  {XKB_KEY_F11,           VTERM_KEY_FUNCTION_0 + 11},
  {XKB_KEY_F12,           VTERM_KEY_FUNCTION_0 + 12},
  {XKB_KEY_F13,           VTERM_KEY_FUNCTION_0 + 13},
  {XKB_KEY_F14,           VTERM_KEY_FUNCTION_0 + 14},
  {XKB_KEY_F15,           VTERM_KEY_FUNCTION_0 + 15},
  {XKB_KEY_F16,           VTERM_KEY_FUNCTION_0 + 16},
  {XKB_KEY_F17,           VTERM_KEY_FUNCTION_0 + 17},
  {XKB_KEY_F18,           VTERM_KEY_FUNCTION_0 + 18},
  {XKB_KEY_F19,           VTERM_KEY_FUNCTION_0 + 19},
  {XKB_KEY_F20,           VTERM_KEY_FUNCTION_0 + 20},

  {XKB_KEY_KP_0,          VTERM_KEY_KP_0},
  {XKB_KEY_KP_1,          VTERM_KEY_KP_1},
  {XKB_KEY_KP_2,          VTERM_KEY_KP_2},
  {XKB_KEY_KP_3,          VTERM_KEY_KP_3},
  {XKB_KEY_KP_4,          VTERM_KEY_KP_4},
  {XKB_KEY_KP_5,          VTERM_KEY_KP_5},
  {XKB_KEY_KP_6,          VTERM_KEY_KP_6},
  {XKB_KEY_KP_7,          VTERM_KEY_KP_7},
  {XKB_KEY_KP_8,          VTERM_KEY_KP_8},
  {XKB_KEY_KP_9,          VTERM_KEY_KP_9}
};
