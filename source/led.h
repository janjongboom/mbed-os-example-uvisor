#ifndef SECURE_LED_H_
#define SECURE_LED_H_

#include "uvisor-lib/uvisor-lib.h"

UVISOR_EXTERN bool (*secure_led_get_value)(void);

#endif
