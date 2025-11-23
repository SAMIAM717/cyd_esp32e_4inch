#ifndef Pins_Arduino_h
#define Pins_Arduino_h

#include <stdint.h>

#define USB_VID 0x303a
#define USB_PID 0x1001

static const uint8_t TX = 1;
static const uint8_t RX = 3;

static const uint8_t TXD2 = 17;
static const uint8_t RXD2 = 16;

static const uint8_t SDA = 21;
static const uint8_t SCL = 22;

static const uint8_t SS = -1;
static const uint8_t MOSI = 13;
static const uint8_t MISO = 12;
static const uint8_t SCK = 14;

static const uint8_t G0 = 0;
static const uint8_t G1 = 1;
static const uint8_t G2 = 2;
static const uint8_t G3 = 3;
static const uint8_t G4 = 4;
static const uint8_t G5 = 5;
static const uint8_t G12 = 12;
static const uint8_t G13 = 13;
static const uint8_t G14 = 14;
static const uint8_t G15 = 15;
static const uint8_t G16 = 16;
static const uint8_t G17 = 17;
static const uint8_t G18 = 18;
static const uint8_t G19 = 19;
static const uint8_t G21 = 21;
static const uint8_t G22 = 22;
static const uint8_t G23 = 23;
static const uint8_t G25 = 25;
static const uint8_t G26 = 26;
static const uint8_t G27 = 27;
static const uint8_t G32 = 32;
static const uint8_t G33 = 33;
static const uint8_t G34 = 34;
static const uint8_t G35 = 35;
static const uint8_t G36 = 36;
static const uint8_t G39 = 39;

#define HAS_BTN 0
#define BTN_ALIAS "\"Ok\""
#define BTN_PIN -1
#define BTN_ACT LOW

#define LED -1
#define LED_ON HIGH
#define LED_OFF LOW

#define HAS_SCREEN 1
#define HAS_TOUCH 1
#define ROTATION 1
#define MINBRIGHT (uint8_t)5

#define FP 1
#define FM 2
#define FG 3

#define USE_HSPI_PORT 1
#define USER_SETUP_LOADED 1
#define ST7796_DRIVER 1
#define TFT_RGB_ORDER TFT_BGR
#define TFT_MOSI 13
#define TFT_SCLK 14
#define TFT_MISO 12
#define TFT_CS 15
#define TFT_DC 2
#define TFT_RST 4
#define TFT_BL 27
#define TFT_WIDTH 320
#define TFT_HEIGHT 480
#define TFT_BACKLIGHT_ON HIGH
#define SMOOTH_FONT 1
#define SPI_FREQUENCY 40000000
#define SPI_READ_FREQUENCY 16000000
#define SPI_TOUCH_FREQUENCY 2500000
#define TOUCH_XPT2046_SPI
#define TOUCH_IRQ 36
#define TOUCH_MOSI 32
#define TOUCH_MISO 39
#define TOUCH_CLK 25
#define TOUCH_CS 33
#define XPT2046_TOUCH_CONFIG_INT_GPIO_NUM TOUCH_IRQ
#define XPT2046_SPI_BUS_MOSI_IO_NUM TOUCH_MOSI
#define XPT2046_SPI_BUS_MISO_IO_NUM TOUCH_MISO
#define XPT2046_SPI_BUS_SCLK_IO_NUM TOUCH_CLK
#define XPT2046_SPI_CONFIG_CS_GPIO_NUM TOUCH_CS

#define TFT_BRIGHT_CHANNEL 0
#define TFT_BRIGHT_FREQ 12000
#define TFT_BRIGHT_BITS 8

#define SPI_SCK_PIN 14
#define SPI_MOSI_PIN 13
#define SPI_MISO_PIN 12
#define SPI_SS_PIN 15

#define GROVE_SDA SDA
#define GROVE_SCL SCL

// BadUSB serial pins - using available GPIO pins
// GPIO 26 and 34 are not used by the display or touch
#define BAD_TX 26
#define BAD_RX 34

#endif /* Pins_Arduino_h */
