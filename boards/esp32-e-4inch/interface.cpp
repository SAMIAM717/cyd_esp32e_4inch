#ifdef ARDUINO

#include <Arduino.h>
#include "core/powerSave.h"
#include "core/utils.h"
#include <globals.h>
#include <interface.h>

#if defined(HAS_TOUCH) && HAS_TOUCH
#include <CYD28_TouchscreenR.h>
static CYD28_TouchR touch(TFT_WIDTH, TFT_HEIGHT);
#endif

#ifndef TFT_BRIGHT_CHANNEL
#define TFT_BRIGHT_CHANNEL 0
#endif
#ifndef TFT_BRIGHT_FREQ
#define TFT_BRIGHT_FREQ 12000
#endif
#ifndef TFT_BRIGHT_BITS
#define TFT_BRIGHT_BITS 8
#endif

/***************************************************************************************
** Function name: _setup_gpio()
** Description:   initial setup for the device
***************************************************************************************/
void _setup_gpio() {
    pinMode(TFT_BL, OUTPUT);
    ledcSetup(TFT_BRIGHT_CHANNEL, TFT_BRIGHT_FREQ, TFT_BRIGHT_BITS);
    ledcAttachPin(TFT_BL, TFT_BRIGHT_CHANNEL);
    ledcWrite(TFT_BRIGHT_CHANNEL, TFT_BACKLIGHT_ON == HIGH ? 255 : 0);

    bruceConfig.rotation = ROTATION;
    bruceConfig.colorInverted = 0;

#if defined(HAS_TOUCH) && HAS_TOUCH
    touch.setRotation(bruceConfig.rotation);
#endif
}

/***************************************************************************************
** Function name: _post_setup_gpio()
** Description:   second stage gpio setup to make a few functions work
***************************************************************************************/
void _post_setup_gpio() {
#if defined(HAS_TOUCH) && HAS_TOUCH
    if (!touch.begin(&tft.getSPIinstance())) {
        Serial.println("Touch controller not detected");
    } else {
        touch.setRotation(bruceConfig.rotation);
        touch.setThreshold(250);
    }
#endif
}

/***************************************************************************************
** Function name: getBattery()
** Description:   Delivers the battery value from 1-100
***************************************************************************************/
int getBattery() { return 0; }

/***************************************************************************************
** Function name: isCharging()
** Description:   Determine whether external power is present
***************************************************************************************/
bool isCharging() { return false; }

/*********************************************************************
** Function: goToDeepSleep
** Puts the device into DeepSleep
**********************************************************************/
void goToDeepSleep() {}

/*********************************************************************
** Function: setBrightness
** Set brightness value
**********************************************************************/
void _setBrightness(uint8_t brightval) {
    if (brightval == 0) {
        ledcWrite(TFT_BRIGHT_CHANNEL, 0);
        return;
    }
    int duty = MINBRIGHT + ((255 - MINBRIGHT) * brightval) / 100;
    duty = constrain(duty, MINBRIGHT, 255);
    ledcWrite(TFT_BRIGHT_CHANNEL, duty);
}

/*********************************************************************
** Function: InputHandler
** Handles the variables PrevPress, NextPress, SelPress, AnyKeyPress and EscPress
**********************************************************************/
void InputHandler(void) {
#if defined(HAS_TOUCH) && HAS_TOUCH
    static unsigned long tm = 0;
    if (millis() - tm > 200 || LongPress) {
        if (touch.touched()) {
            auto p = touch.getPointScaled();
            tm = millis();

            if (!wakeUpScreen()) AnyKeyPress = true;
            else return;

            // Align the library-scaled coordinates with our logical screen size.
            const int32_t rawWidth = (bruceConfig.rotation % 2 == 0) ? TFT_HEIGHT : TFT_WIDTH;
            const int32_t rawHeight = (bruceConfig.rotation % 2 == 0) ? TFT_WIDTH : TFT_HEIGHT;
            int32_t scaledX = (rawWidth > 0) ? (int32_t)p.x * tftWidth / rawWidth : p.x;
            int32_t scaledY = (rawHeight > 0) ? (int32_t)p.y * tftHeight / rawHeight : p.y;

            // Invert coordinates
            scaledX = tftWidth - scaledX;
            scaledY = tftHeight - scaledY;

            touchPoint.x = constrain(scaledX, 0, tftWidth);
            touchPoint.y = constrain(scaledY, 0, tftHeight);
            touchPoint.pressed = true;
            touchHeatMap(touchPoint);
        } else {
            touchPoint.pressed = false;
        }
    }
#else
    (void)LongPress;
#endif
}

/*********************************************************************
** Function: powerOff
** Turns off the device (or tries to)
**********************************************************************/
void powerOff() {}

/*********************************************************************
** Function: checkReboot
** Btn logic to turn off the device
**********************************************************************/
void checkReboot() {}

#endif // ARDUINO
