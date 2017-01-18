/*
 * Copyright (c) 2013-2016, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "led.h"
#ifdef FEATURE_UVISOR
#include "uvisor-lib/uvisor-lib.h"
#endif
#include "mbed.h"
#include "main-hw.h"
#include "key_derive.h"

#ifdef FEATURE_UVISOR
typedef struct {
    InterruptIn * sw;
    DigitalOut * led;
    RawSerial * pc;
    int caller_id;
    Thread * rpc_thread;
    Thread * tls_thread;
} my_box_context;

static const UvisorBoxAclItem acl[] = {
};

static void my_box_main(const void *);
static bool get_value(void);

UVISOR_BOX_NAMESPACE(NULL);
UVISOR_BOX_HEAPSIZE(8192 * 2.5);
UVISOR_BOX_MAIN(my_box_main, osPriorityNormal, UVISOR_BOX_STACK_SIZE);
UVISOR_BOX_CONFIG(my_box, acl, UVISOR_BOX_STACK_SIZE, my_box_context);

UVISOR_BOX_RPC_GATEWAY_SYNC (my_box, secure_led_get_value, get_value, bool, void);

RawSerial *pc;

static bool get_value(void)
{
    return *uvisor_ctx->led;
}

static void my_box_switch_irq(void)
{
    /* flip LED state */
    *uvisor_ctx->led = !*uvisor_ctx->led;

    /* print LED state on serial port */
    uvisor_ctx->pc->printf(
        "\nPressed SW2, printing from interrupt - LED changed to %i\r\n\r\n",
        (int)(*uvisor_ctx->led));
}

static void listen_for_rpc()
{
    uvisor_ctx->pc->printf("listen_for_rpc\r\n");

    static const TFN_Ptr my_fn_array[] = {
        (TFN_Ptr) get_value
    };

    while (1) {
        int status;

        /* NOTE: This serializes all access to the number store! */
        status = rpc_fncall_waitfor(my_fn_array, 1, &uvisor_ctx->caller_id, UVISOR_WAIT_FOREVER);

        if (status) {
            uvisor_ctx->pc->printf("Failure is not an option.\r\n");
            uvisor_error(USER_NOT_ALLOWED);
        }
    }
}
#endif

void do_key_derivation() {
#if FEATURE_UVISOR
    uvisor_ctx->pc->printf("calling tls\r\n");
#endif

  uint32_t errcode;
  AKA_protection_ctx_t ctx;
	uint8_t wrap_key[PROFILE_PROTECTION_WRAP_KEY_LEN];
  uint8_t priv_key[PROFILE_PROTECTION_PLEN]={
  0x04,0x42,0x88,0x5A,0x2C,0xDD,0xA8,0x8D,0xC2,0x7B,0xED,0xEC,0x36,0xD5,0xD9,0x24,
  0x58,0x1F,0xA5,0x93,0xEA,0xBC,0x63,0x5A,0xFB,0x42,0x25,0x34,0xBB,0x88,0x40,0xBB};
  uint8_t wrappedKeys[1 + 2*PROFILE_PROTECTION_PLEN + PROFILE_PROTECTION_HASH_LEN]={
  0x04,0x51,0xA3,0x72,0x5C,0x6F,0xD4,0xC1,0xAD,0x32,0xE1,0x9F,0xBE,0x86,0x8B,0xF9,
  0x82,0x6E,0xCC,0xE6,0x76,0x4A,0x7C,0x55,0x55,0xC7,0x4B,0xFE,0x45,0xDF, 0xD7,0x21,
  0x39,0x2A,0xC5,0x68,0x2D,0x38,0xFD,0xAA,0xEE,0x99,0x7F,0x25,0x76,0x8B,0xCB,0xFB,
  0x18,0x2A,0x00,0xCA,0xB4,0x6C,0x55,0x0B,0xA8,0x50,0x0C,0x24,0xEF,0x57,0x2E,0xD9,
  0x54,0x77,0xE2,0x54,0xB9,0xC4,0x72,0xB4,0xE4,0xD3,0xE5,0xEB,0xE8,0xEA,0xEF,0xE1,
  0x76,0x0D,0xE0,0x4E,0x50,0xF1,0x73,0x93,0x7E,0xB6,0xA2,0x7D,0x53,0xB7,0x65,0x19,
  0xB1};

      /* Setup profile protection ctx */
    memset(&ctx,0,sizeof(ctx));
    ctx.priv_key_p = priv_key;
    ctx.priv_key_len = sizeof(priv_key);

#ifdef FEATURE_UVISOR
    uvisor_ctx->pc->printf("derive...\r\n");
#else
    printf("derive...\r\n");
#endif

    /* Derive wrapping key */
    errcode = AKA_Profile_Derive_Wrapping_Key(wrappedKeys,
                                            1 + 2*PROFILE_PROTECTION_PLEN + PROFILE_PROTECTION_HASH_LEN,
  	                                        &ctx, wrap_key);

#ifdef FEATURE_UVISOR
    uvisor_ctx->pc->printf("Done running errcode is %d\r\n", errcode);
#endif
}

#ifdef FEATURE_UVISOR
static void my_box_main(const void *)
{
    wait_ms(500);

    /* allocate serial port to ensure that code in this secure box
     * won't touch handle in the default security context when printing */
    if(!(pc = new RawSerial(USBTX, USBRX)))
        return;
    /* remember serial driver for IRQ routine */
    uvisor_ctx->pc = pc;

    uvisor_ctx->rpc_thread = new Thread(osPriorityNormal);
    uvisor_ctx->rpc_thread->start(&listen_for_rpc);

    uvisor_ctx->tls_thread = new Thread(osPriorityNormal, DEFAULT_STACK_SIZE);
    uvisor_ctx->tls_thread->start(&do_key_derivation);

    /* allocate a box-specific LED */
    if(!(uvisor_ctx->led = new DigitalOut(SECURE_LED)))
        pc->printf("ERROR: failed to allocate memories for LED\n");
    else
    {
        /* turn LED off by default */
        *uvisor_ctx->led = LED_OFF;

        /* allocate a box-specific switch handler */
        if(!(uvisor_ctx->sw = new InterruptIn(SW2))) {
            pc->printf("ERROR: failed to allocate memories for SW1\n");
            delete uvisor_ctx->led;
        }
        else
        {
            /* register handler for switch SW1 */
            uvisor_ctx->sw->mode(PullUp);
            uvisor_ctx->sw->fall(my_box_switch_irq);
        }
    }
}
#endif
