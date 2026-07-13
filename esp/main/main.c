#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "rabbit.h" 

static const char *TAG = "CRYPTO_CORE";

// pin setup
#define UART1_PORT_NUM        UART_NUM_1
#define UART1_RX_PIN          GPIO_NUM_4   
#define UART1_TX_PIN          UART_PIN_NO_CHANGE

#define UART2_PORT_NUM        UART_NUM_2
#define UART2_TX_PIN          GPIO_NUM_17  
#define UART2_RX_PIN          UART_PIN_NO_CHANGE

#define BLUE_LED_GPIO         GPIO_NUM_2   

#define PIN_RESET_SOURCE      GPIO_NUM_18  
#define PIN_RESET_DETECT      GPIO_NUM_19  

#define BUF_SIZE              4096
#define KEY_SIZE              16
#define IV_SIZE               8
#define UART_QUEUE_SIZE       20

typedef enum {
    STATE_WAIT_KEY,
    STATE_WAIT_IV,
    STATE_STREAMING
} system_state_t;

volatile system_state_t current_state;
volatile int processing_timeout = 0; 

uint8_t key_buffer[KEY_SIZE];
uint8_t iv_buffer[IV_SIZE];
uint8_t key_len = 0;
uint8_t iv_len = 0;

scheduler rabbit_ctx;
QueueHandle_t uart1_queue;

// Test functions
void load_key(const uint8_t *raw_key, rabbit_word_t *key) {
    for (uint8_t i = 0; i < RABBIT_KEY_WORDS; ++i) key[i] = 0;
    for (uint8_t i = 0; i < 16; i++) {
        key[i >> ENCRYPT_SHIFT] |= ((rabbit_word_t)raw_key[i]) << (
            ((sizeof(rabbit_word_t) - 1) - (i & (sizeof(rabbit_word_t) - 1))) * 8
        );
    }
}

void load_iv(const uint8_t *raw_iv, rabbit_word_t *iv) {
    for (uint8_t i = 0; i < RABBIT_IV_WORDS; ++i) iv[i] = 0;
    for (uint8_t i = 0; i < 8; i++) {
        iv[i >> ENCRYPT_SHIFT] |= ((rabbit_word_t)raw_iv[i]) << (
            ((sizeof(rabbit_word_t) - 1) - (i & (sizeof(rabbit_word_t) - 1))) * 8
        );
    }
}

// RFC test vectors
int runVectorTest(const char* test_name, const uint8_t* raw_key, const uint8_t* raw_iv, const uint8_t ref[3][16], int use_iv) {
    scheduler state;
    rabbit_word_t key[RABBIT_KEY_WORDS];
    load_key(raw_key, key);
    
    rabbit_word_t iv_val[RABBIT_IV_WORDS];
    const rabbit_word_t *iv_ptr = NULL;
    if (use_iv) {
        load_iv(raw_iv, iv_val);
        iv_ptr = iv_val;
    }

    initScheduler(&state, key, iv_ptr);

    int passed = 1;
    for (int block = 0; block < 3; ++block) {
        for (int i = 0; i < 16; ++i) {
            uint8_t out = encryptByte(&state, 0); 
            uint8_t expected = ref[block][15 - i]; 
            
            if (out != expected) {
                ESP_LOGE(TAG, "[ %s ] FAILED at block %d, stream byte %d: expected %02X, got %02X", 
                       test_name, block, i, expected, out);
                passed = 0;
            }
        }
    }
    
    if (passed) ESP_LOGI(TAG, "[ %s ] PASSED", test_name);
    return passed;
}

bool rfcTests() {
    ESP_LOGW(TAG, "--- RUNNING RFC 4503 TEST VECTORS ---");
    int passed = 1;

    // A.1.1
    const uint8_t key1_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t ref1_1[3][16] = {
        {0xB1, 0x57, 0x54, 0xF0, 0x36, 0xA5, 0xD6, 0xEC, 0xF5, 0x6B, 0x45, 0x26, 0x1C, 0x4A, 0xF7, 0x02},
        {0x88, 0xE8, 0xD8, 0x15, 0xC5, 0x9C, 0x0C, 0x39, 0x7B, 0x69, 0x6C, 0x47, 0x89, 0xC6, 0x8A, 0xA7},
        {0xF4, 0x16, 0xA1, 0xC3, 0x70, 0x0C, 0xD4, 0x51, 0xDA, 0x68, 0xD1, 0x88, 0x16, 0x73, 0xD6, 0x96}
    };
    passed &= runVectorTest("A.1.1 (Zero Key, No IV)", key1_1, NULL, ref1_1, 0);

    // A.1.2
    const uint8_t key1_2[16] = {0x91, 0x28, 0x13, 0x29, 0x2E, 0x3D, 0x36, 0xFE, 0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC};
    const uint8_t ref1_2[3][16] = {
        {0x3D, 0x2D, 0xF3, 0xC8, 0x3E, 0xF6, 0x27, 0xA1, 0xE9, 0x7F, 0xC3, 0x84, 0x87, 0xE2, 0x51, 0x9C},
        {0xF5, 0x76, 0xCD, 0x61, 0xF4, 0x40, 0x5B, 0x88, 0x96, 0xBF, 0x53, 0xAA, 0x85, 0x54, 0xFC, 0x19},
        {0xE5, 0x54, 0x74, 0x73, 0xFB, 0xDB, 0x43, 0x50, 0x8A, 0xE5, 0x3B, 0x20, 0x20, 0x4D, 0x4C, 0x5E}
    };
    passed &= runVectorTest("A.1.2 (Test Key 1, No IV)", key1_2, NULL, ref1_2, 0);

    // A.1.3
    const uint8_t key1_3[16] = {0x83, 0x95, 0x74, 0x15, 0x87, 0xE0, 0xC7, 0x33, 0xE9, 0xE9, 0xAB, 0x01, 0xC0, 0x9B, 0x00, 0x43};
    const uint8_t ref1_3[3][16] = {
        {0x0C, 0xB1, 0x0D, 0xCD, 0xA0, 0x41, 0xCD, 0xAC, 0x32, 0xEB, 0x5C, 0xFD, 0x02, 0xD0, 0x60, 0x9B},
        {0x95, 0xFC, 0x9F, 0xCA, 0x0F, 0x17, 0x01, 0x5A, 0x7B, 0x70, 0x92, 0x11, 0x4C, 0xFF, 0x3E, 0xAD},
        {0x96, 0x49, 0xE5, 0xDE, 0x8B, 0xFC, 0x7F, 0x3F, 0x92, 0x41, 0x47, 0xAD, 0x3A, 0x94, 0x74, 0x28}
    };
    passed &= runVectorTest("A.1.3 (Test Key 2, No IV)", key1_3, NULL, ref1_3, 0);

    // A.2.1
    const uint8_t key2_1[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t iv2_1[8]   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t ref2_1[3][16] = {
        {0xC6, 0xA7, 0x27, 0x5E, 0xF8, 0x54, 0x95, 0xD8, 0x7C, 0xCD, 0x5D, 0x37, 0x67, 0x05, 0xB7, 0xED},
        {0x5F, 0x29, 0xA6, 0xAC, 0x04, 0xF5, 0xEF, 0xD4, 0x7B, 0x8F, 0x29, 0x32, 0x70, 0xDC, 0x4A, 0x8D},
        {0x2A, 0xDE, 0x82, 0x2B, 0x29, 0xDE, 0x6C, 0x1E, 0xE5, 0x2B, 0xDB, 0x8A, 0x47, 0xBF, 0x8F, 0x66}
    };
    passed &= runVectorTest("A.2.1 (Zero Key, Zero IV)", key2_1, iv2_1, ref2_1, 1);

    // A.2.2
    const uint8_t iv2_2[8]   = {0xC3, 0x73, 0xF5, 0x75, 0xC1, 0x26, 0x7E, 0x59};
    const uint8_t ref2_2[3][16] = {
        {0x1F, 0xCD, 0x4E, 0xB9, 0x58, 0x00, 0x12, 0xE2, 0xE0, 0xDC, 0xCC, 0x92, 0x22, 0x01, 0x7D, 0x6D},
        {0xA7, 0x5F, 0x4E, 0x10, 0xD1, 0x21, 0x25, 0x01, 0x7B, 0x24, 0x99, 0xFF, 0xED, 0x93, 0x6F, 0x2E},
        {0xEB, 0xC1, 0x12, 0xC3, 0x93, 0xE7, 0x38, 0x39, 0x23, 0x56, 0xBD, 0xD0, 0x12, 0x02, 0x9B, 0xA7}
    };
    passed &= runVectorTest("A.2.2 (Zero Key, Test IV 1)", key2_1, iv2_2, ref2_2, 1);

    // A.2.3
    const uint8_t iv2_3[8]   = {0xA6, 0xEB, 0x56, 0x1A, 0xD2, 0xF4, 0x17, 0x27};
    const uint8_t ref2_3[3][16] = {
        {0x44, 0x5A, 0xD8, 0xC8, 0x05, 0x85, 0x8D, 0xBF, 0x70, 0xB6, 0xAF, 0x23, 0xA1, 0x51, 0x10, 0x4D},
        {0x96, 0xC8, 0xF2, 0x79, 0x47, 0xF4, 0x2C, 0x5B, 0xAE, 0xAE, 0x67, 0xC6, 0xAC, 0xC3, 0x5B, 0x03},
        {0x9F, 0xCB, 0xFC, 0x89, 0x5F, 0xA7, 0x1C, 0x17, 0x31, 0x3D, 0xF0, 0x34, 0xF0, 0x15, 0x51, 0xCB}
    };
    passed &= runVectorTest("A.2.3 (Zero Key, Test IV 2)", key2_1, iv2_3, ref2_3, 1);

    ESP_LOGW(TAG, "--- END OF TESTS ---");
    return (passed == 1);
}

// Memory functions
bool load_key_from_memory() {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READONLY, &my_handle) != ESP_OK) return false;
    size_t required_size = KEY_SIZE;
    esp_err_t err = nvs_get_blob(my_handle, "rabbit_key", key_buffer, &required_size);
    nvs_close(my_handle);
    return (err == ESP_OK && required_size == KEY_SIZE);
}

void save_key_to_memory() {
    nvs_handle_t my_handle;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &my_handle));
    ESP_ERROR_CHECK(nvs_set_blob(my_handle, "rabbit_key", key_buffer, KEY_SIZE));
    ESP_ERROR_CHECK(nvs_commit(my_handle));
    nvs_close(my_handle);
    ESP_LOGI(TAG, "New Key SECURELY SAVED to NVS.");
}


void init_hardware(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    uart_config_t uart_config = {
        .baud_rate = 2000000, .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE, .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_param_config(UART1_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART1_PORT_NUM, UART1_TX_PIN, UART1_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(UART1_PORT_NUM, BUF_SIZE * 4, BUF_SIZE * 4, UART_QUEUE_SIZE, &uart1_queue, 0));
    ESP_ERROR_CHECK(uart_set_rx_full_threshold(UART1_PORT_NUM, 120));
    ESP_ERROR_CHECK(uart_set_rx_timeout(UART1_PORT_NUM, 10));

    ESP_ERROR_CHECK(uart_param_config(UART2_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART2_PORT_NUM, UART2_TX_PIN, UART2_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    ESP_ERROR_CHECK(uart_driver_install(UART2_PORT_NUM, BUF_SIZE * 4, BUF_SIZE * 4, 0, NULL, 0));

    gpio_set_direction(BLUE_LED_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_RESET_SOURCE, GPIO_MODE_OUTPUT);
    gpio_set_level(PIN_RESET_SOURCE, 0); 
    
    gpio_config_t det_conf = {.pin_bit_mask = (1ULL << PIN_RESET_DETECT), .mode = GPIO_MODE_INPUT, .pull_up_en = 1};
    gpio_config(&det_conf); 
}

// stream task
void IRAM_ATTR crypto_task(void *pvParameters) {
    static uint8_t data[BUF_SIZE] __attribute__((aligned(4))); 
    rabbit_word_t r_key[RABBIT_KEY_WORDS];
    rabbit_word_t r_iv[RABBIT_IV_WORDS];
    uart_event_t event;
    
    while (1) {
        if (xQueueReceive(uart1_queue, (void * )&event, portMAX_DELAY)) {
            if (event.type == UART_DATA) {
                int length = uart_read_bytes(UART1_PORT_NUM, data, (event.size > BUF_SIZE) ? BUF_SIZE : event.size, portMAX_DELAY);
                int i = 0;
                while (i < length) {
                    if (current_state == STATE_WAIT_KEY) {
                        key_buffer[key_len++] = data[i++];
                        if (key_len == KEY_SIZE) {
                            save_key_to_memory();
                            current_state = STATE_WAIT_IV;
                            ESP_LOGI(TAG, "16-byte Key saved. Waiting for 8-byte IV...");
                        }
                    } 
                    else if (current_state == STATE_WAIT_IV) {
                        iv_buffer[iv_len++] = data[i++];
                        if (iv_len == IV_SIZE) {
                            // init rabbit context
                            load_key(key_buffer, r_key);
                            load_iv(iv_buffer, r_iv);
                            initScheduler(&rabbit_ctx, r_key, r_iv);
                            
                            current_state = STATE_STREAMING;
                            ESP_LOGI(TAG, "IV accepted! Crypto stream STARTED.");
                        }
                    } 
                    else if (current_state == STATE_STREAMING) {
                        uint8_t* ptr = &data[i];
                        int remaining = length - i;
                        // ensure memory is aligned
                        while (remaining > 0 && ((uintptr_t)ptr & 0x03) != 0) {
                            *ptr = encryptByte(&rabbit_ctx, *ptr);
                            ptr++;
                            remaining--;
                        }
                        // optimised encryption
                        uint32_t* word_ptr = (uint32_t*)ptr;
                        int word_count = remaining / 4;
                        
                        for (int w = 0; w < word_count; w++) {
                            word_ptr[w] = encryptWord(&rabbit_ctx, word_ptr[w]);
                        }

                        // handle remainder
                        ptr = (uint8_t*)(word_ptr + word_count);
                        remaining -= word_count * 4;
                        while (remaining > 0) {
                            *ptr = encryptByte(&rabbit_ctx, *ptr);
                            ptr++;
                            remaining--;
                        }

                        // send result
                        uart_write_bytes(UART2_PORT_NUM, (const char*)&data[i], length - i);
                        
                        processing_timeout = 3; 
                        i = length; 
                    }
                }
            }else if (event.type == UART_FIFO_OVF) {
                ESP_LOGE(TAG, "UART HW FIFO Overflow! Data lost.");
                uart_flush_input(UART1_PORT_NUM);
                xQueueReset(uart1_queue);
            }
        }
    }
    free(data);
    vTaskDelete(NULL);
}

void app_main(void) {
    init_hardware();

    // handle nvs in one point
    nvs_handle_t my_handle;
    bool nvs_opened = (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK);
    // key reset
    if (nvs_opened && gpio_get_level(PIN_RESET_DETECT) == 0) {
        ESP_LOGI(TAG, "!!! RESET JUMPER DETECTED !!!");
        nvs_erase_key(my_handle, "rabbit_key");
        nvs_erase_key(my_handle, "tests_passed");
        nvs_commit(my_handle);
        ESP_LOGI(TAG, "Memory wiped.");
        for(int i = 0; i < 3; i++) {
            gpio_set_level(BLUE_LED_GPIO, 1); vTaskDelay(pdMS_TO_TICKS(80));
            gpio_set_level(BLUE_LED_GPIO, 0); vTaskDelay(pdMS_TO_TICKS(80));
        }
    }

    uint8_t tests_passed = 0;
    if (nvs_opened) {
        nvs_get_u8(my_handle, "tests_passed", &tests_passed);
        // launch tests
        if (tests_passed == 0) {
            ESP_LOGI(TAG, "First boot. Running Crypto Tests...");
            if (rfcTests()) {
                nvs_set_u8(my_handle, "tests_passed", 1);
                nvs_commit(my_handle);
                ESP_LOGI(TAG, "Tests passed! Flag saved.");
            } else {
                nvs_close(my_handle); // we won't need it
                ESP_LOGE(TAG, "CRYPTO TESTS FAILED! Halting.");
                while(1) {
                    gpio_set_level(BLUE_LED_GPIO, 1); vTaskDelay(pdMS_TO_TICKS(100));
                    gpio_set_level(BLUE_LED_GPIO, 0); vTaskDelay(pdMS_TO_TICKS(100));
                }
            }
        } else {
            ESP_LOGI(TAG, "Crypto tests already verified. Skipping.");
        }

        // load key
        size_t required_size = KEY_SIZE;
        if (nvs_get_blob(my_handle, "rabbit_key", key_buffer, &required_size) == ESP_OK && required_size == KEY_SIZE) {
            ESP_LOGI(TAG, "Key found. Ready for IV.");
            current_state = STATE_WAIT_IV;
        } else {
            ESP_LOGI(TAG, "No Key. Waiting for 16-byte Key...");
            current_state = STATE_WAIT_KEY;
        }
        
        nvs_close(my_handle); // close for good
    } else {
        current_state = STATE_WAIT_KEY;
    }

    // run on sepparate core for future usage
    xTaskCreatePinnedToCore(crypto_task, "crypto_task", 8192, NULL, 20, NULL, 1);

    // LED control
    uint32_t ticks = 0;
    while (1) {
        switch (current_state) {
            case STATE_WAIT_KEY:
                gpio_set_level(BLUE_LED_GPIO, 1); 
                break;
            case STATE_WAIT_IV:
                gpio_set_level(BLUE_LED_GPIO, (ticks % 14 < 7) ? 1 : 0); 
                break;
            case STATE_STREAMING:
                if (processing_timeout > 0) {
                    gpio_set_level(BLUE_LED_GPIO, ticks % 2); 
                    processing_timeout--;
                } else {
                    gpio_set_level(BLUE_LED_GPIO, 0); 
                }
                break;
        }
        ticks++;
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}