/*
 * Conquer Online Stealth Protection Module
 *
 * This module provides kernel-level protection for conquer.exe by implementing
 * an intelligent deception layer that fools anti-cheat engines. Instead of
 * denying access (which ACes detect), we grant "fake" handles with stripped
 * permissions, making the AC believe it succeeded while preventing real memory
 * access.
 *
 * Authors: Custom implementation on top of KSystemInformer
 */

#include <kph.h>
#include <trace.h>

KPH_PAGED_FILE();

// Target process name to protect
KPH_PROTECTED_DATA_SECTION_RO_PUSH();
static const UNICODE_STRING KphpConquerProcessName =
    RTL_CONSTANT_STRING(L"conquer.exe");
KPH_PROTECTED_DATA_SECTION_RO_POP();

// Access masks that MUST be stripped from any handle to the protected process
// These are the ones anti-cheats use to scan memory
#define KPH_CONQUER_FORBIDDEN_PROCESS_ACCESS                                   \
  (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |                 \
   PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION |                       \
   PROCESS_SUSPEND_RESUME)

// Access we pretend to give (so AC doesn't know it got nothing real)
#define KPH_CONQUER_DECOY_PROCESS_ACCESS                                       \
  (PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)

// Thread access deception
#define KPH_CONQUER_FORBIDDEN_THREAD_ACCESS                                    \
  (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |           \
   THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION)

/**
 * \brief Checks if a process name matches "conquer.exe".
 *
 * \param[in] ProcessContext The process context to check.
 *
 * \return TRUE if the process is conquer.exe, FALSE otherwise.
 */
_IRQL_requires_max_(APC_LEVEL) BOOLEAN
    KphIsConquerProcess(_In_ PKPH_PROCESS_CONTEXT ProcessContext) {
  KPH_PAGED_CODE();

  if (!ProcessContext)
    return FALSE;

  return RtlEqualUnicodeString(&ProcessContext->ImageName,
                               &KphpConquerProcessName,
                               TRUE // case-insensitive
  );
}

/**
 * \brief Applies "Deception Mode" access stripping for conquer.exe.
 *
 * Instead of blocking access entirely (which ACs detect via
 * STATUS_ACCESS_DENIED), we allow the open but strip all dangerous access bits.
 * The AC thinks it succeeded in opening a handle but cannot actually
 * read/write/suspend the game process.
 *
 * \param[in,out] DesiredAccess Pointer to the desired access to modify.
 * \param[in] IsThread TRUE if stripping thread access, FALSE for process.
 */
_IRQL_requires_max_(APC_LEVEL) VOID
    KphApplyConquerStealthAccess(_Inout_ PACCESS_MASK DesiredAccess,
                                 _In_ BOOLEAN IsThread) {
  ACCESS_MASK original;
  ACCESS_MASK stripped;

  KPH_PAGED_CODE();

  original = *DesiredAccess;

  if (IsThread) {
    // Strip all dangerous thread access bits
    stripped = original & ~KPH_CONQUER_FORBIDDEN_THREAD_ACCESS;
  } else {
    // Strip all dangerous process access bits
    // Keep only "decoy" bits so the AC returns SUCCESS but is harmless
    stripped = original & ~KPH_CONQUER_FORBIDDEN_PROCESS_ACCESS;

    // Add back safe bits if they were requested, to make the handle look
    // "valid"
    if (original &
        (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION))
      stripped |= KPH_CONQUER_DECOY_PROCESS_ACCESS;
  }

  KphTracePrint(TRACE_LEVEL_VERBOSE, PROTECTION,
                "[Conquer Stealth] Stripping access 0x%08x -> 0x%08x (%s)",
                original, stripped, IsThread ? "thread" : "process");

  *DesiredAccess = stripped;
}

/**
 * \brief Checks if an actor process is a known anti-cheat or system monitor.
 *
 * Known ACs: TqClient.dll loader, TqNDProtect.dll host, etc.
 * Returns TRUE for any non-verified external process attempting access.
 *
 * \param[in] Actor The process attempting access.
 *
 * \return TRUE if we should apply stealth deception, FALSE to allow normally.
 */
_IRQL_requires_max_(APC_LEVEL) BOOLEAN
    KphShouldApplyConquerStealth(_In_ PKPH_PROCESS_CONTEXT Actor,
                                 _In_ PKPH_PROCESS_CONTEXT Target) {
  KPH_PAGED_CODE();

  // Only apply stealth when the TARGET is conquer.exe
  if (!KphIsConquerProcess(Target))
    return FALSE;

  // Don't stealth ourselves (allow System Informer full access)
  if (KphTestProcessContextState(Actor, KPH_PROCESS_STATE_MAXIMUM))
    return FALSE;

  // The process is trying to access conquer.exe from an unverified/external
  // process Apply deception stealth instead of hard block
  return !KphTestProcessContextState(Actor, KPH_PROCESS_STATE_MEDIUM);
}
