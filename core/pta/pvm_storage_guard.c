// SPDX-License-Identifier: BSD-2-Clause
/* Test policy: the protected storage volume belongs to FF-A VM 1.
 * A VM id is a hypervisor identity, not guest-image attestation. */
#include <kernel/pseudo_ta.h>
#include <kernel/virtualization.h>
#include <tee_api_defines.h>
#include <kernel/tee_common_otp.h>
#include <storage_huk.h>

/* Emulator fixture HUK: provisioned by the trusted test controller, never copied
 * to the emulated Host filesystem. Real devices must use their hardware HUK. */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *key)
{
    static const uint8_t huk[HW_UNIQUE_KEY_LENGTH] = STORAGE_FIXTURE_HUK;
    memcpy(key->data, huk, sizeof(huk));
    return TEE_SUCCESS;
}
#define GUARD_UUID {0x2fc0af42,0x31e4,0x4ce1,{0x96,0x24,0xe4,0x41,0xb1,0x1c,0x6a,0x93}}
static TEE_Result invoke(void *ctx __unused, uint32_t cmd, uint32_t types,
                         TEE_Param p[TEE_NUM_PARAMS] __unused)
{
    if (cmd || types != TEE_PARAM_TYPES(0, 0, 0, 0))
        return TEE_ERROR_BAD_PARAMETERS;
    return virt_get_current_guest_id() == 1 ? TEE_SUCCESS : TEE_ERROR_ACCESS_DENIED;
}
pseudo_ta_register(.uuid = GUARD_UUID, .name = "pvm.storage.guard",
                   .flags = PTA_DEFAULT_FLAGS, .invoke_command_entry_point = invoke);
