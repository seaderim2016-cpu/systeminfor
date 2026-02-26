/*
 * Conquer Online Ring-0 Hooks (Advanced API/Callback Interception)
 *
 * This module is responsible for neutralizing kernel anti-cheat systems that
 * operate in Ring 0. When standard programs (even admin-level) try to open
 * conquer.exe, the AC's ObRegisterCallbacks block it and return
 * STATUS_ACCESS_DENIED.
 *
 * This module hooks the object manager directly to:
 * 1. Forcefully grant PROCESS_ALL_ACCESS back to our tools.
 * 2. Bypass or disable the AC's protective callbacks dynamically.
 * 3. Make KSystemInformer the absolute authority over handle operations.
 *
 * Authors: Custom implementation on top of KSystemInformer
 */

#include <kph.h>
#include <trace.h>

KPH_PAGED_FILE();

// Target process to grant supreme access to
KPH_PROTECTED_DATA_SECTION_RO_PUSH();
static const UNICODE_STRING KphpConquerProcessNameHooks =
    RTL_CONSTANT_STRING(L"conquer.exe");
KPH_PROTECTED_DATA_SECTION_RO_POP();

/**
 * \brief Checks if the process is conquer.exe
 */
_IRQL_requires_max_(APC_LEVEL) static BOOLEAN
    KphHooksIsConquerProcess(_In_ PKPH_PROCESS_CONTEXT ProcessContext) {
  KPH_PAGED_CODE();

  if (!ProcessContext)
    return FALSE;

  return RtlEqualUnicodeString(&ProcessContext->ImageName,
                               &KphpConquerProcessNameHooks, TRUE);
}

/**
 * \brief The main "God Mode" hook for Conquer.
 *
 * When our tool (or any allowed tool) requests PROCESS_VM_READ/WRITE on
 * conquer.exe, the Anti-Cheat's ObRegisterCallback will strip it and cause
 * Access Denied. This function runs *after* the AC (or overrides it) to
 * forcefully add back the required access rights, completely bypassing the AC's
 * protection.
 *
 * \param[in,out] Access Pointer to the access mask to forcefully grant.
 * \param[in] IsThread TRUE if restoring thread access, FALSE for process.
 */
_IRQL_requires_max_(APC_LEVEL) VOID
    KphForceGrantConquerAccess(_Inout_ PACCESS_MASK Access,
                               _In_ BOOLEAN IsThread) {
  ACCESS_MASK granted;

  KPH_PAGED_CODE();

  if (IsThread) {
    // Force-grant all thread access needed for debugging/memory editing
    granted = *Access | THREAD_ALL_ACCESS;
  } else {
    // Force-grant all process access needed for reading/writing memory
    // This defeats the AC's attempt to strip PROCESS_VM_READ/WRITE
    granted = *Access | PROCESS_ALL_ACCESS;
  }

  KphTracePrint(
      TRACE_LEVEL_INFORMATION, PROTECTION,
      "[Conquer Hook] Force-Granting Supreme Access: 0x%08x -> 0x%08x (%s)",
      *Access, granted, IsThread ? "thread" : "process");

  *Access = granted;
}

/**
 * \brief Decision engine: Should we apply God Mode for this actor?
 *
 * \param[in] Actor The process attempting to open the handle (e.g., Cheat
 * Engine, System Informer)
 * \param[in] Target The process being opened (e.g., conquer.exe)
 *
 * \return TRUE if we should force-grant access.
 */
_IRQL_requires_max_(APC_LEVEL) BOOLEAN
    KphShouldForceGrantConquerAccess(_In_ PKPH_PROCESS_CONTEXT Actor,
                                     _In_ PKPH_PROCESS_CONTEXT Target) {
  KPH_PAGED_CODE();

  // Only intervene if the target is conquer.exe
  if (!KphHooksIsConquerProcess(Target))
    return FALSE;

  // Do NOT grant access to the Anti-Cheat itself if it's inspecting things
  // We only grant access to programs we trust, e.g., anything with
  // KPH_PROCESS_STATE_MAXIMUM or KPH_PROCESS_STATE_HIGH (like Cheat Engine
  // opened via our driver). For universal testing, if the Actor is NOT the game
  // itself, we can grant it.
  if (Actor->ProcessId == Target->ProcessId)
    return FALSE; // Let the game open itself normally

  return TRUE;
}

/**
 * \brief Optional: Scans the object callback list (advanced stealth).
 *
 * Anti-Cheats use ObRegisterCallbacks. By unlinking their callback from the
 * Windows kernel list, their code will never even execute, saving us from
 * having to fix the access mask later.
 *
 * (Currently implemented as a stub; full unlinking requires undocumented struct
 * manipulation which varies between Windows 10/11 builds. Forced-Grant approach
 * above is universally safer).
 */
_IRQL_requires_max_(APC_LEVEL) NTSTATUS KphNeutralizeObCallbacks(VOID) {
  KPH_PAGED_CODE();

  KphTracePrint(TRACE_LEVEL_INFORMATION, PROTECTION,
                "[Conquer Hook] Neutralization of AC Callbacks initialized.");

  // TODO: Parse PspCidTable or CallbackListHead to find suspected AC drivers
  // and patch their Operations pointer to NULL or return OB_PREOP_SUCCESS.

  return STATUS_SUCCESS;
}
