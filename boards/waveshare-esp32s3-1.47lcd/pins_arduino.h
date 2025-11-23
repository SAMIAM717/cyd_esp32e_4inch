// Waveshare ESP32-S3 1.47" LCD board pinout and TFT_eSPI config
#ifndef Pins_Arduino_h
#define Pins_Arduino_h

#include <stdint.h>

// SPI (LCD + SD) per user-provided pinout
#define SPI_SS_PIN 39   // LCD_CS
#define SPI_MOSI_PIN 2  // MOSI
#define SPI_MISO_PIN 42 // MISO (may be NC on some modules)
#define SPI_SCK_PIN 1   // SCLK

static const uint8_t SS = SPI_SS_PIN;
static const uint8_t MOSI = SPI_MOSI_PIN;
static const uint8_t MISO = SPI_MISO_PIN;
static const uint8_t SCK = SPI_SCK_PIN;

// SD card (if the base has one; SD_CS provided)
#define SDCARD_CS 38
#define SDCARD_SCK SPI_SCK_PIN
#define SDCARD_MISO SPI_MISO_PIN
#define SDCARD_MOSI SPI_MOSI_PIN

// Touch (I2C)
#define GROVE_SDA 15 // TP_SDA
#define GROVE_SCL 7  // TP_SCL
static const uint8_t SDA = GROVE_SDA;
static const uint8_t SCL = GROVE_SCL;
#define TP_INT 17
#define TP_RST 16

// Backlight and control
#define TFT_BL 6        // LCD_BL (PWM capable)
#define PIN_POWER_ON -1 // No power control pin needed on this board

// Buttons (if any). For now map to a basic trio; adjust if your base has keys
#define HAS_3_BUTTONS
#define SEL_BTN 0
#define UP_BTN 14
#define DW_BTN 13
#define BTN_ACT LOW
#define BTN_ALIAS "\"OK\""

// Battery sense (if wired). Default to an available ADC pin
#define BAT_PIN 4

// TFT_eSPI over SPI, ST7789 on 1.47" 172x320 typically
#define USER_SETUP_LOADED
#define ST7789_DRIVER 1
#define TFT_WIDTH 172
#define TFT_HEIGHT 320
#define CGRAM_OFFSET
#define TFT_RGB_ORDER TFT_BGR
#define TFT_INVERSION_ON
#define TFT_SPI_MODE SPI_MODE3
#define TFT_BACKLIGHT_ON HIGH

// SPI wiring
#define TFT_MOSI SPI_MOSI_PIN
#define TFT_MISO SPI_MISO_PIN
#define TFT_SCLK SPI_SCK_PIN
#define TFT_CS SPI_SS_PIN
#define TFT_DC 41
#define TFT_RST 40

// Frequencies
#define SPI_FREQUENCY 27000000
#define SPI_READ_FREQUENCY 16000000

// Display/BRUCE integration
#define HAS_SCREEN
#define ROTATION 3
#define MINBRIGHT (uint8_t)1

// Font Sizes
#define FP 1
#define FM 2
#define FG 3
#define SMOOTH_FONT 1

// LED logic
#define LED_ON HIGH
#define LED_OFF LOW

// IR pins (default to available GPIOs, adjust if you have specific IR hardware)
#define LED 10
#define RXLED 11

// USB BadUSB support
#define USB_as_HID 1

#endif /* Pins_Arduino_h */
