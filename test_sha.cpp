
#include <Arduino.h>
#include <mbedtls/sha256.h>
void setup() {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_free(&ctx);
}
void loop() {}
