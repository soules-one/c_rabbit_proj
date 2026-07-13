idf_component_register(SRCS "main.c" "../../lib/rabbit.c"
                    INCLUDE_DIRS "." "../../lib")

target_compile_definitions(${COMPONENT_LIB} PRIVATE RABBIT_32BIT ESP_PLATFORM)
