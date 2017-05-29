/*
 * Copyright (c) 2017 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Note that this driver is only intended to provide enough functionality
 * for the diagnostics shell. As a result, some features, especially those
 * that may not correctly be emulated for USB keyboards, will not be
 * supported. This includes any communication with the keyboard itself.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <kern/error.h>
#include <kern/init.h>
#include <kern/intr.h>
#include <kern/macros.h>
#include <machine/atkbd.h>
#include <machine/atcons.h>
#include <machine/io.h>

#define ATKBD_PORT_DATA             0x60
#define ATKBD_PORT_STATUS           0x64
#define ATKBD_PORT_CMD              0x64

#define ATKBD_STATUS_OUT_FULL       0x01
#define ATKBD_STATUS_IN_FULL        0x02
#define ATKBD_STATUS_PARITY_ERROR   0x80

#define ATKBD_CMD_RDCONF            0x20
#define ATKBD_CMD_WRCONF            0x60
#define ATKBD_CMD_DIS2              0xa7
#define ATKBD_CMD_EN2               0xa8
#define ATKBD_CMD_DIS1              0xad
#define ATKBD_CMD_EN1               0xae

#define ATKBD_CONF_ENINT1           0x01
#define ATKBD_CONF_ENINT2           0x02
#define ATKBD_CONF_ENTRANS          0x40

#define ATKBD_INTR1                 1

enum atkbd_key_id {
    ATKBD_KEY_INVALID = 0,
    ATKBD_KEY_1 = 1,
    ATKBD_KEY_2,
    ATKBD_KEY_3,
    ATKBD_KEY_4,
    ATKBD_KEY_5,
    ATKBD_KEY_6,
    ATKBD_KEY_7,
    ATKBD_KEY_8,
    ATKBD_KEY_9,
    ATKBD_KEY_0,
    ATKBD_KEY_DASH,
    ATKBD_KEY_EQUAL,
    ATKBD_KEY_BACKSLASH,
    ATKBD_KEY_BACKSPACE,

    ATKBD_KEY_TAB,
    ATKBD_KEY_Q,
    ATKBD_KEY_W,
    ATKBD_KEY_E,
    ATKBD_KEY_R,
    ATKBD_KEY_T,
    ATKBD_KEY_Y,
    ATKBD_KEY_U,
    ATKBD_KEY_I,
    ATKBD_KEY_O,
    ATKBD_KEY_P,
    ATKBD_KEY_OBRACKET,
    ATKBD_KEY_CBRACKET,
    ATKBD_KEY_ENTER,

    ATKBD_KEY_CAPSLOCK,
    ATKBD_KEY_A,
    ATKBD_KEY_S,
    ATKBD_KEY_D,
    ATKBD_KEY_F,
    ATKBD_KEY_G,
    ATKBD_KEY_H,
    ATKBD_KEY_J,
    ATKBD_KEY_K,
    ATKBD_KEY_L,
    ATKBD_KEY_SEMICOLON,
    ATKBD_KEY_QUOTE,

    ATKBD_KEY_LSHIFT,
    ATKBD_KEY_Z,
    ATKBD_KEY_X,
    ATKBD_KEY_C,
    ATKBD_KEY_V,
    ATKBD_KEY_B,
    ATKBD_KEY_N,
    ATKBD_KEY_M,
    ATKBD_KEY_COMMA,
    ATKBD_KEY_DOT,
    ATKBD_KEY_SLASH,
    ATKBD_KEY_RSHIFT,

    ATKBD_KEY_LCTRL,
    ATKBD_KEY_ALT,
    ATKBD_KEY_SPACE,
    ATKBD_KEY_ALTGR,
    ATKBD_KEY_RCTRL,

    ATKBD_KEY_INSERT,
    ATKBD_KEY_DELETE,
    ATKBD_KEY_HOME,
    ATKBD_KEY_END,
    ATKBD_KEY_PGUP,
    ATKBD_KEY_PGDOWN,

    ATKBD_KEY_LEFT,
    ATKBD_KEY_BOTTOM,
    ATKBD_KEY_RIGHT,
    ATKBD_KEY_UP,

    ATKBD_KEY_KP_NUMLOCK,
    ATKBD_KEY_KP_SLASH,
    ATKBD_KEY_KP_STAR,
    ATKBD_KEY_KP_MINUS,
    ATKBD_KEY_KP_HOME,
    ATKBD_KEY_KP_UP,
    ATKBD_KEY_KP_PGUP,
    ATKBD_KEY_KP_PLUS,
    ATKBD_KEY_KP_LEFT,
    ATKBD_KEY_KP_5,
    ATKBD_KEY_KP_RIGHT,
    ATKBD_KEY_KP_END,
    ATKBD_KEY_KP_BOTTOM,
    ATKBD_KEY_KP_PGDOWN,
    ATKBD_KEY_KP_ENTER,
    ATKBD_KEY_KP_INS,
    ATKBD_KEY_KP_DEL,
};

#define ATKBD_KM_SHIFT      0x01 /* Shift / caps lock modifier applies */
#define ATKBD_KM_KP         0x02 /* Num lock modifier applies */
#define ATKBD_KM_CTL        0x04 /* Unmodified key is a control character */

struct atkbd_key {
    int modifiers;
    enum atkbd_key_id id;
};

static const struct atkbd_key atkbd_keys[] = {
    [0x16] = { ATKBD_KM_SHIFT, ATKBD_KEY_1 },
    [0x1e] = { ATKBD_KM_SHIFT, ATKBD_KEY_2 },
    [0x26] = { ATKBD_KM_SHIFT, ATKBD_KEY_3 },
    [0x25] = { ATKBD_KM_SHIFT, ATKBD_KEY_4 },
    [0x2e] = { ATKBD_KM_SHIFT, ATKBD_KEY_5 },
    [0x36] = { ATKBD_KM_SHIFT, ATKBD_KEY_6 },
    [0x3d] = { ATKBD_KM_SHIFT, ATKBD_KEY_7 },
    [0x3e] = { ATKBD_KM_SHIFT, ATKBD_KEY_8 },
    [0x46] = { ATKBD_KM_SHIFT, ATKBD_KEY_9 },
    [0x45] = { ATKBD_KM_SHIFT, ATKBD_KEY_0 },
    [0x4e] = { ATKBD_KM_SHIFT, ATKBD_KEY_DASH },
    [0x55] = { ATKBD_KM_SHIFT, ATKBD_KEY_EQUAL },
    [0x5d] = { ATKBD_KM_SHIFT, ATKBD_KEY_BACKSLASH },
    [0x66] = { 0, ATKBD_KEY_BACKSPACE },

    [0x0d] = { 0, ATKBD_KEY_TAB },
    [0x15] = { ATKBD_KM_SHIFT, ATKBD_KEY_Q },
    [0x1d] = { ATKBD_KM_SHIFT, ATKBD_KEY_W },
    [0x24] = { ATKBD_KM_SHIFT, ATKBD_KEY_E },
    [0x2d] = { ATKBD_KM_SHIFT, ATKBD_KEY_R },
    [0x2c] = { ATKBD_KM_SHIFT, ATKBD_KEY_T },
    [0x35] = { ATKBD_KM_SHIFT, ATKBD_KEY_Y },
    [0x3c] = { ATKBD_KM_SHIFT, ATKBD_KEY_U },
    [0x43] = { ATKBD_KM_SHIFT, ATKBD_KEY_I },
    [0x44] = { ATKBD_KM_SHIFT, ATKBD_KEY_O },
    [0x4d] = { ATKBD_KM_SHIFT, ATKBD_KEY_P },
    [0x54] = { ATKBD_KM_SHIFT, ATKBD_KEY_OBRACKET },
    [0x5b] = { ATKBD_KM_SHIFT, ATKBD_KEY_CBRACKET },
    [0x5a] = { 0, ATKBD_KEY_ENTER },

    [0x58] = { ATKBD_KM_CTL, ATKBD_KEY_CAPSLOCK },
    [0x1c] = { ATKBD_KM_SHIFT, ATKBD_KEY_A },
    [0x1b] = { ATKBD_KM_SHIFT, ATKBD_KEY_S },
    [0x23] = { ATKBD_KM_SHIFT, ATKBD_KEY_D },
    [0x2b] = { ATKBD_KM_SHIFT, ATKBD_KEY_F },
    [0x34] = { ATKBD_KM_SHIFT, ATKBD_KEY_G },
    [0x33] = { ATKBD_KM_SHIFT, ATKBD_KEY_H },
    [0x3b] = { ATKBD_KM_SHIFT, ATKBD_KEY_J },
    [0x42] = { ATKBD_KM_SHIFT, ATKBD_KEY_K },
    [0x4b] = { ATKBD_KM_SHIFT, ATKBD_KEY_L },
    [0x4c] = { ATKBD_KM_SHIFT, ATKBD_KEY_SEMICOLON },
    [0x52] = { ATKBD_KM_SHIFT, ATKBD_KEY_QUOTE },

    [0x12] = { ATKBD_KM_CTL, ATKBD_KEY_LSHIFT },
    [0x1a] = { ATKBD_KM_SHIFT, ATKBD_KEY_Z },
    [0x22] = { ATKBD_KM_SHIFT, ATKBD_KEY_X },
    [0x21] = { ATKBD_KM_SHIFT, ATKBD_KEY_C },
    [0x2a] = { ATKBD_KM_SHIFT, ATKBD_KEY_V },
    [0x32] = { ATKBD_KM_SHIFT, ATKBD_KEY_B },
    [0x31] = { ATKBD_KM_SHIFT, ATKBD_KEY_N },
    [0x3a] = { ATKBD_KM_SHIFT, ATKBD_KEY_M },
    [0x41] = { ATKBD_KM_SHIFT, ATKBD_KEY_COMMA },
    [0x49] = { ATKBD_KM_SHIFT, ATKBD_KEY_DOT },
    [0x4a] = { ATKBD_KM_SHIFT, ATKBD_KEY_SLASH },
    [0x59] = { ATKBD_KM_CTL, ATKBD_KEY_RSHIFT },

    [0x14] = { ATKBD_KM_CTL, ATKBD_KEY_LCTRL },
    [0x11] = { ATKBD_KM_CTL, ATKBD_KEY_ALT },
    [0x29] = { 0, ATKBD_KEY_SPACE },

    [0x77] = { ATKBD_KM_CTL, ATKBD_KEY_KP_NUMLOCK },
    [0x7c] = { 0, ATKBD_KEY_KP_STAR },
    [0x7b] = { 0, ATKBD_KEY_KP_MINUS },
    [0x6c] = { ATKBD_KM_KP, ATKBD_KEY_KP_HOME },
    [0x75] = { ATKBD_KM_KP, ATKBD_KEY_KP_UP },
    [0x7d] = { ATKBD_KM_KP, ATKBD_KEY_KP_PGUP },
    [0x79] = { 0, ATKBD_KEY_KP_PLUS },
    [0x6b] = { ATKBD_KM_KP, ATKBD_KEY_KP_LEFT },
    [0x73] = { 0, ATKBD_KEY_KP_5 },
    [0x74] = { ATKBD_KM_KP, ATKBD_KEY_KP_RIGHT },
    [0x69] = { ATKBD_KM_KP, ATKBD_KEY_KP_END },
    [0x72] = { ATKBD_KM_KP, ATKBD_KEY_KP_BOTTOM },
    [0x7a] = { ATKBD_KM_KP, ATKBD_KEY_KP_PGDOWN },
    [0x70] = { ATKBD_KM_CTL | ATKBD_KM_KP, ATKBD_KEY_KP_INS },
    [0x71] = { ATKBD_KM_KP, ATKBD_KEY_KP_DEL },
};

static const struct atkbd_key atkbd_e0_keys[] = {
    [0x11] = { ATKBD_KM_CTL, ATKBD_KEY_ALTGR },
    [0x14] = { ATKBD_KM_CTL, ATKBD_KEY_RCTRL },

    [0x70] = { ATKBD_KM_CTL, ATKBD_KEY_INSERT },
    [0x71] = { 0, ATKBD_KEY_DELETE },
    [0x6c] = { 0, ATKBD_KEY_HOME },
    [0x69] = { 0, ATKBD_KEY_END },
    [0x7d] = { 0, ATKBD_KEY_PGUP },
    [0x7a] = { 0, ATKBD_KEY_PGDOWN },

    [0x6b] = { 0, ATKBD_KEY_LEFT },
    [0x72] = { 0, ATKBD_KEY_BOTTOM },
    [0x74] = { 0, ATKBD_KEY_RIGHT },
    [0x75] = { 0, ATKBD_KEY_UP },

    [0x4a] = { 0, ATKBD_KEY_KP_SLASH },
    [0x5a] = { 0, ATKBD_KEY_KP_ENTER },
};

static const char *atkbd_chars[] = {
    [ATKBD_KEY_1] = "1",
    [ATKBD_KEY_2] = "2",
    [ATKBD_KEY_3] = "3",
    [ATKBD_KEY_4] = "4",
    [ATKBD_KEY_5] = "5",
    [ATKBD_KEY_6] = "6",
    [ATKBD_KEY_7] = "7",
    [ATKBD_KEY_8] = "8",
    [ATKBD_KEY_9] = "9",
    [ATKBD_KEY_0] = "0",
    [ATKBD_KEY_DASH] = "-",
    [ATKBD_KEY_EQUAL] = "=",
    [ATKBD_KEY_BACKSLASH] = "\\",
    [ATKBD_KEY_BACKSPACE] = "\b",

    [ATKBD_KEY_TAB] = "\t",
    [ATKBD_KEY_Q] = "q",
    [ATKBD_KEY_W] = "w",
    [ATKBD_KEY_E] = "e",
    [ATKBD_KEY_R] = "r",
    [ATKBD_KEY_T] = "t",
    [ATKBD_KEY_Y] = "y",
    [ATKBD_KEY_U] = "u",
    [ATKBD_KEY_I] = "i",
    [ATKBD_KEY_O] = "o",
    [ATKBD_KEY_P] = "p",
    [ATKBD_KEY_OBRACKET] = "[",
    [ATKBD_KEY_CBRACKET] = "]",
    [ATKBD_KEY_ENTER] = "\n",

    [ATKBD_KEY_A] = "a",
    [ATKBD_KEY_S] = "s",
    [ATKBD_KEY_D] = "d",
    [ATKBD_KEY_F] = "f",
    [ATKBD_KEY_G] = "g",
    [ATKBD_KEY_H] = "h",
    [ATKBD_KEY_J] = "j",
    [ATKBD_KEY_K] = "k",
    [ATKBD_KEY_L] = "l",
    [ATKBD_KEY_SEMICOLON] = ";",
    [ATKBD_KEY_QUOTE] = "'",

    [ATKBD_KEY_Z] = "z",
    [ATKBD_KEY_X] = "x",
    [ATKBD_KEY_C] = "c",
    [ATKBD_KEY_V] = "v",
    [ATKBD_KEY_B] = "b",
    [ATKBD_KEY_N] = "n",
    [ATKBD_KEY_M] = "m",
    [ATKBD_KEY_COMMA] = ",",
    [ATKBD_KEY_DOT] = ".",
    [ATKBD_KEY_SLASH] = "/",

    [ATKBD_KEY_SPACE] = " ",

    [ATKBD_KEY_DELETE] = "\e[3~",

    [ATKBD_KEY_LEFT] = "\e[D",
    [ATKBD_KEY_BOTTOM] = "\e[B",
    [ATKBD_KEY_RIGHT] = "\e[C",
    [ATKBD_KEY_UP] = "\e[A",

    [ATKBD_KEY_KP_SLASH] = "/",
    [ATKBD_KEY_KP_STAR] = "*",
    [ATKBD_KEY_KP_MINUS] = "-",
    [ATKBD_KEY_KP_PLUS] = "+",
    [ATKBD_KEY_KP_5] = "5",
    [ATKBD_KEY_KP_ENTER] = "\n",
    [ATKBD_KEY_KP_DEL] = "\e[3~",
};

static const char *atkbd_shift_chars[] = {
    [ATKBD_KEY_1] = "!",
    [ATKBD_KEY_2] = "@",
    [ATKBD_KEY_3] = "#",
    [ATKBD_KEY_4] = "$",
    [ATKBD_KEY_5] = "%",
    [ATKBD_KEY_6] = "^",
    [ATKBD_KEY_7] = "&",
    [ATKBD_KEY_8] = "*",
    [ATKBD_KEY_9] = "(",
    [ATKBD_KEY_0] = ")",
    [ATKBD_KEY_DASH] = "_",
    [ATKBD_KEY_EQUAL] = "+",
    [ATKBD_KEY_BACKSLASH] = "|",

    [ATKBD_KEY_Q] = "Q",
    [ATKBD_KEY_W] = "W",
    [ATKBD_KEY_E] = "E",
    [ATKBD_KEY_R] = "R",
    [ATKBD_KEY_T] = "T",
    [ATKBD_KEY_Y] = "Y",
    [ATKBD_KEY_U] = "U",
    [ATKBD_KEY_I] = "I",
    [ATKBD_KEY_O] = "O",
    [ATKBD_KEY_P] = "P",
    [ATKBD_KEY_OBRACKET] = "{",
    [ATKBD_KEY_CBRACKET] = "}",

    [ATKBD_KEY_A] = "A",
    [ATKBD_KEY_S] = "S",
    [ATKBD_KEY_D] = "D",
    [ATKBD_KEY_F] = "F",
    [ATKBD_KEY_G] = "G",
    [ATKBD_KEY_H] = "H",
    [ATKBD_KEY_J] = "J",
    [ATKBD_KEY_K] = "K",
    [ATKBD_KEY_L] = "L",
    [ATKBD_KEY_SEMICOLON] = ":",
    [ATKBD_KEY_QUOTE] = "\"",

    [ATKBD_KEY_Z] = "Z",
    [ATKBD_KEY_X] = "X",
    [ATKBD_KEY_C] = "C",
    [ATKBD_KEY_V] = "V",
    [ATKBD_KEY_B] = "B",
    [ATKBD_KEY_N] = "N",
    [ATKBD_KEY_M] = "M",
    [ATKBD_KEY_COMMA] = "<",
    [ATKBD_KEY_DOT] = ">",
    [ATKBD_KEY_SLASH] = "?",
};

static const char *atkbd_kp_chars[] = {
    [ATKBD_KEY_KP_HOME] = "7",
    [ATKBD_KEY_KP_UP] = "8",
    [ATKBD_KEY_KP_PGUP] = "9",
    [ATKBD_KEY_KP_LEFT] = "4",
    [ATKBD_KEY_KP_RIGHT] = "6",
    [ATKBD_KEY_KP_END] = "1",
    [ATKBD_KEY_KP_BOTTOM] = "2",
    [ATKBD_KEY_KP_PGDOWN] = "3",
    [ATKBD_KEY_KP_INS] = "0",
    [ATKBD_KEY_KP_DEL] = ".",
};

#define ATKBD_KF_E0         0x01
#define ATKBD_KF_F0         0x02
#define ATKBD_KF_LSHIFT     0x04
#define ATKBD_KF_RSHIFT     0x08
#define ATKBD_KF_NUMLOCK    0x10
#define ATKBD_KF_CAPSLOCK   0x20
#define ATKBD_KF_SCROLLLOCK 0x40

#define ATKBD_KF_SHIFT      (ATKBD_KF_CAPSLOCK  \
                             | ATKBD_KF_RSHIFT  \
                             | ATKBD_KF_LSHIFT)

/*
 * These flags are only accessed during interrupt handling and don't
 * require additional synchronization.
 */
static unsigned int atkbd_flags;

static uint8_t
atkbd_read_data(void)
{
    return io_read_byte(ATKBD_PORT_DATA);
}

static void
atkbd_write_data(uint8_t data)
{
    io_write_byte(ATKBD_PORT_DATA, data);
}

static uint8_t
atkbd_read_status(void)
{
    return io_read_byte(ATKBD_PORT_STATUS);
}

static void
atkbd_write_cmd(uint8_t cmd)
{
    io_write_byte(ATKBD_PORT_CMD, cmd);
}

static int
atkbd_out_wait(void)
{
    uint8_t status;

    for (;;) {
        status = atkbd_read_status();

        if (status & ATKBD_STATUS_OUT_FULL) {
            break;
        }
    }

    if (status & ATKBD_STATUS_PARITY_ERROR) {
        printf("atkbd: parity error\n");
        return ERROR_IO;
    }

    return 0;
}

static void
atkbd_in_wait(void)
{
    uint8_t status;

    for (;;) {
        status = atkbd_read_status();

        if (!(status & ATKBD_STATUS_IN_FULL)) {
            break;
        }
    }
}

static int
atkbd_read(uint8_t *datap, bool wait)
{
    uint8_t status;
    int error;

    if (wait) {
        error = atkbd_out_wait();

        if (error) {
            return error;
        }
    } else {
        status = atkbd_read_status();

        if (!(status & ATKBD_STATUS_OUT_FULL)) {
            return ERROR_AGAIN;
        }
    }

    *datap = atkbd_read_data();
    return 0;
}

static void
atkbd_write(uint8_t data)
{
    atkbd_in_wait();
    atkbd_write_data(data);
}

static void
atkbd_flush(void)
{
    uint8_t status;
    int error;

    do {
        error = atkbd_read(&status, false);
    } while (!error);
}

static int __init
atkbd_disable(void)
{
    uint8_t byte;
    int error;

    atkbd_write_cmd(ATKBD_CMD_DIS1);
    atkbd_write_cmd(ATKBD_CMD_DIS2);

    atkbd_flush();

    atkbd_write_cmd(ATKBD_CMD_RDCONF);
    error = atkbd_read(&byte, true);

    if (error) {
        return error;
    }

    byte &= ~(ATKBD_CONF_ENTRANS | ATKBD_CONF_ENINT2 | ATKBD_CONF_ENINT1);
    atkbd_write_cmd(ATKBD_CMD_WRCONF);
    atkbd_write(byte);

    return 0;
}

static int __init
atkbd_enable(void)
{
    uint8_t byte;
    int error;

    atkbd_write_cmd(ATKBD_CMD_EN1);

    atkbd_write_cmd(ATKBD_CMD_RDCONF);
    error = atkbd_read(&byte, true);

    if (error) {
        return error;
    }

    byte &= ~(ATKBD_CONF_ENTRANS | ATKBD_CONF_ENINT2);
    byte |= ATKBD_CONF_ENINT1;
    atkbd_write_cmd(ATKBD_CMD_WRCONF);
    atkbd_write(byte);

    atkbd_flush();

    return 0;
}

static void
atkbd_toggle_numlock(void)
{
    atkbd_flags ^= ATKBD_KF_NUMLOCK;
}

static void
atkbd_toggle_capslock(void)
{
    atkbd_flags ^= ATKBD_KF_CAPSLOCK;
}

static void
atkbd_key_process_chars(const struct atkbd_key *key,
                        const char **chars, size_t size)
{
    const char *s;

    if (key->id >= size) {
        return;
    }

    if (atkbd_flags & ATKBD_KF_F0) {
        return;
    }

    s = chars[key->id];

    if (s != NULL) {
        while (*s != '\0') {
            atcons_intr(*s);
            s++;
        }
    }
}

static void
atkbd_key_process_shift(const struct atkbd_key *key)
{
    atkbd_key_process_chars(key, atkbd_shift_chars,
                            ARRAY_SIZE(atkbd_shift_chars));
}

static void
atkbd_key_process_kp(const struct atkbd_key *key)
{
    atkbd_key_process_chars(key, atkbd_kp_chars,
                            ARRAY_SIZE(atkbd_kp_chars));
}

static void
atkbd_key_process_ctl(const struct atkbd_key *key)
{
    switch (key->id) {
    case ATKBD_KEY_LSHIFT:
        if (atkbd_flags & ATKBD_KF_F0) {
            atkbd_flags &= ~ATKBD_KF_LSHIFT;
        } else {
            atkbd_flags |= ATKBD_KF_LSHIFT;
        }

        break;
    case ATKBD_KEY_RSHIFT:
        if (atkbd_flags & ATKBD_KF_F0) {
            atkbd_flags &= ~ATKBD_KF_RSHIFT;
        } else {
            atkbd_flags |= ATKBD_KF_RSHIFT;
        }

        break;
    case ATKBD_KEY_KP_NUMLOCK:
        if (!(atkbd_flags & ATKBD_KF_F0)) {
            atkbd_toggle_numlock();
        }

        break;
    case ATKBD_KEY_CAPSLOCK:
        if (!(atkbd_flags & ATKBD_KF_F0)) {
            atkbd_toggle_capslock();
        }
    default:
        break;
    }
}

static void
atkbd_key_process(const struct atkbd_key *key)
{
    if (key->id == ATKBD_KEY_INVALID) {
        return;
    }

    if ((key->modifiers & ATKBD_KM_SHIFT) && (atkbd_flags & ATKBD_KF_SHIFT)) {
        atkbd_key_process_shift(key);
    } else if ((key->modifiers & ATKBD_KM_KP)
               && (atkbd_flags & ATKBD_KF_NUMLOCK)) {
        atkbd_key_process_kp(key);
    } else if (key->modifiers & ATKBD_KM_CTL) {
        atkbd_key_process_ctl(key);
    } else {
        atkbd_key_process_chars(key, atkbd_chars, ARRAY_SIZE(atkbd_chars));
    }

    atkbd_flags &= ~ATKBD_KF_F0;
}

static void
atkbd_process_e0_code(uint8_t code)
{
    if (code == 0xf0) {
        atkbd_flags |= ATKBD_KF_F0;
        return;
    }

    if (code >= ARRAY_SIZE(atkbd_keys)) {
        return;
    }

    atkbd_key_process(&atkbd_e0_keys[code]);
    atkbd_flags &= ~ATKBD_KF_E0;
}

static void
atkbd_process_code(uint8_t code)
{
    if (code == 0xe0) {
        atkbd_flags |= ATKBD_KF_E0;
        return;
    } else if (code == 0xf0) {
        atkbd_flags |= ATKBD_KF_F0;
        return;
    }

    if (code >= ARRAY_SIZE(atkbd_keys)) {
        return;
    }

    atkbd_key_process(&atkbd_keys[code]);
}

static int
atkbd_intr(void *arg)
{
    uint8_t code;
    int error;

    (void)arg;

    for (;;) {
        error = atkbd_read(&code, false);

        if (error) {
            return 0;
        }

        if (atkbd_flags & ATKBD_KF_E0) {
            atkbd_process_e0_code(code);
        } else {
            atkbd_process_code(code);
        }
    }

    return 0;
}

void __init
atkbd_setup(void)
{
    int error;

    error = atkbd_disable();

    if (error) {
        return;
    }

    error = intr_register(ATKBD_INTR1, atkbd_intr, NULL);

    if (error) {
        printf("atkbd: error: unable to register interrupt handler\n");
        return;
    }

    error = atkbd_enable();

    if (error) {
        return;
    }
}
