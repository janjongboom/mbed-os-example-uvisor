#ifdef FEATURE_UVISOR
#include "mbed.h"
#include "uvisor-lib/uvisor-lib.h"

struct box_context {
    uint32_t unused;
};

static const UvisorBoxAclItem acl[] = {
};

static void box_debug_main(const void *);

/* Configure the debug box. */
UVISOR_BOX_NAMESPACE(NULL);
UVISOR_BOX_HEAPSIZE(8192);
UVISOR_BOX_MAIN(box_debug_main, osPriorityNormal, UVISOR_BOX_STACK_SIZE);
UVISOR_BOX_CONFIG(box_debug, acl, UVISOR_BOX_STACK_SIZE, box_context);

static uint32_t get_version(void) {
    return 0;
}

static void halt_error(int reason) {
    printf("We halted with reason %i\r\n", reason);
    /* We will now reboot. */
}

static void box_debug_main(const void *)
{
    /* Debug box driver -- Version 0 */
    static const TUvisorDebugDriver driver = {
        get_version,
        halt_error
    };

    /* Register the debug box with uVisor. */
    uvisor_debug_init(&driver);
}
#endif
