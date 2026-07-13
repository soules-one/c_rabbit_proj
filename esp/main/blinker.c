#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "LED_BUTTON_CTRL";

#define BUTTON_BOOT_GPIO  GPIO_NUM_0
#define BLUE_LED_GPIO     GPIO_NUM_2

typedef enum {
    LED_STATE_OFF = 0,     
    LED_STATE_CONSTANT,    
    LED_STATE_BLINKING,
    LED_STATE_MAX        
} led_mode_t;

static led_mode_t current_mode = LED_STATE_OFF;

void init_hardware(void) {
    gpio_config_t led_conf = {
        .pin_bit_mask = (1ULL << BLUE_LED_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&led_conf);

    gpio_config_t btn_conf = {
        .pin_bit_mask = (1ULL << BUTTON_BOOT_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&btn_conf);
}

void app_main(void) {
    init_hardware();
    ESP_LOGI(TAG, "Hardware initialized. System started in OFF mode.");

    uint32_t loop_counter = 0;

    while (1) {
        if (gpio_get_level(BUTTON_BOOT_GPIO) == 0) {
            vTaskDelay(pdMS_TO_TICKS(50));
            
            if (gpio_get_level(BUTTON_BOOT_GPIO) == 0) {
                current_mode = (current_mode + 1) % LED_STATE_MAX;
                ESP_LOGI(TAG, "Button pressed! Switching to mode: %d", current_mode);
                
                while (gpio_get_level(BUTTON_BOOT_GPIO) == 0) {
                    vTaskDelay(pdMS_TO_TICKS(20));
                }
            }
        }

        switch (current_mode) {
            case LED_STATE_OFF:
                gpio_set_level(BLUE_LED_GPIO, 0);
                vTaskDelay(pdMS_TO_TICKS(100));
                break;

            case LED_STATE_CONSTANT:
                gpio_set_level(BLUE_LED_GPIO, 1);
                vTaskDelay(pdMS_TO_TICKS(100));
                break;

            case LED_STATE_BLINKING:
                if (loop_counter % 2 == 0) {
                    gpio_set_level(BLUE_LED_GPIO, 1);
                } else {
                    gpio_set_level(BLUE_LED_GPIO, 0);
                }
                vTaskDelay(pdMS_TO_TICKS(250));
                break;

            default:
                break;
        }

        loop_counter++;
    }
}