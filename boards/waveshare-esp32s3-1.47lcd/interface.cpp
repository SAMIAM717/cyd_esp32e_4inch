// Waveshare ESP32-S3 1.47 inch LCD interface initialization
#include "pins_arduino.h"
#include <globals.h>
#include <interface.h>

/***************************************************************************************
** Function name: _setup_gpio()
** Description:   initial setup for the device
***************************************************************************************/
void _setup_gpio() {
    // Setup buttons if your board has them
    pinMode(SEL_BTN, INPUT_PULLUP);
    pinMode(UP_BTN, INPUT_PULLUP);
    pinMode(DW_BTN, INPUT_PULLUP);

    // Setup backlight pin
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);

    // Setup battery sense pin
    pinMode(BAT_PIN, INPUT);

    Serial.begin(115200);
}

/***************************************************************************************
** Function name: _post_setup_gpio()
** Description:   second stage gpio setup
***************************************************************************************/
void _post_setup_gpio() {
    // Additional setup if needed
}

/***************************************************************************************
** Function name: getBattery()
** Description:   Delivers the battery value from 1-100
***************************************************************************************/
int getBattery() {
    // Basic voltage reading - adjust voltage divider ratio if needed
    int raw = analogRead(BAT_PIN);
    // Map to 0-100% (adjust these values based on your battery)
    int percent = map(raw, 0, 4095, 0, 100);
    return (percent < 0) ? 0 : (percent >= 100) ? 100 : percent;
}

/*********************************************************************
** Function: setBrightness
** set brightness value
**********************************************************************/
void _setBrightness(uint8_t brightval) {
    if (brightval == 0) {
        analogWrite(TFT_BL, 0);
    } else {
        int bl = MINBRIGHT + round(((255 - MINBRIGHT) * brightval / 100));
        analogWrite(TFT_BL, bl);
    }
}

/*********************************************************************
** Function: InputHandler
** Handles the variables PrevPress, NextPress, SelPress, AnyKeyPress and EscPress
**********************************************************************/
void InputHandler(void) {
    // Basic button handling
    if (digitalRead(SEL_BTN) == BTN_ACT) {
        delay(50); // debounce
        if (digitalRead(SEL_BTN) == BTN_ACT) {
            SelPress = true;
            AnyKeyPress = true;
        }
    }

    if (digitalRead(UP_BTN) == BTN_ACT) {
        delay(50);
        if (digitalRead(UP_BTN) == BTN_ACT) {
            PrevPress = true;
            AnyKeyPress = true;
        }
    }

    if (digitalRead(DW_BTN) == BTN_ACT) {
        delay(50);
        if (digitalRead(DW_BTN) == BTN_ACT) {
            NextPress = true;
            AnyKeyPress = true;
        }
    }
}

/*********************************************************************
** Function: powerOff
** Turns off the device
**********************************************************************/
void powerOff() {
    // Simple power off by turning off backlight and entering deep sleep
    digitalWrite(TFT_BL, LOW);
    esp_deep_sleep_start();
}

/*********************************************************************
** Function: goToDeepSleep
** Puts the device into DeepSleep
**********************************************************************/
void goToDeepSleep() {
    digitalWrite(TFT_BL, LOW);
    esp_deep_sleep_start();
}

/*********************************************************************
** Function: checkReboot
** Button logic to turn off the device
**********************************************************************/
void checkReboot() {
    // Basic implementation - can be enhanced
}

/***************************************************************************************
** Function name: isCharging()
** Description:   Determines if the device is charging
***************************************************************************************/
bool isCharging() {
    return false; // No charging detection on this basic board
}
