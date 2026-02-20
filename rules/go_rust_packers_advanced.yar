/* go_rust_packers_advanced.yar
 * Cross-platform: Go / Rust binaries and static packers
 * Author: ivan-gate
 */

import "elf"
import "pe"
import "macho"

/* ================= Helpers ================= */

private rule __is_elf   { condition: uint32(0) == 0x7F454C46 and elf }
private rule __is_pe    { condition: uint16(0) == 0x5A4D and pe }
private rule __is_macho {
  condition:
    uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
    uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA
}
private rule __smallish { condition: filesize > 20KB and filesize < 200MB }

/* ================= A) GO identification & behaviors ================= */

/* A1: Надёжная идентификация Go-бинарей (в т.ч. PE/ELF/Mach-O) */
rule GO_Runtime_Fingerprint
{
  meta: category="go" severity="info"
  strings:
    $g0 = ".gopclntab" ascii
    $g1 = "go build id" ascii nocase
    $g2 = "runtime.main" ascii
    $g3 = "golang.org/" ascii
    $g4 = "GOMAXPROCS" ascii
  condition:
    __smallish and ( $g0 or $g1 or ( 2 of ($g2,$g3,$g4) ) )
}

/* A2: Go loader/exfil: net/http + JSON/Base64 + exec */
rule GO_Loader_HTTP_Base64_Exec
{
  meta: category="go-loader" severity="high"
  strings:
    $h1 = "net/http" ascii
    $h2 = "http.NewRequest" ascii
    $j1 = "encoding/json" ascii
    $b6 = "encoding/base64" ascii
    $ex = "os/exec" ascii
    $sh = "exec.Command" ascii
  condition:
    __smallish and GO_Runtime_Fingerprint and ( ( $h1 or $h2 ) and ( $j1 or $b6 ) and ( $ex or $sh ) )
}

/* A3: Go syscall/injection-ish примитивы */
rule GO_Syscall_And_Process_Primitives
{
  meta: category="go-injection" severity="medium"
  strings:
    $sc1 = "syscall.Syscall" ascii
    $sc2 = "syscall.Syscall6" ascii
    $dl1 = "dlopen" ascii
    $dl2 = "dlsym" ascii
    $va  = "VirtualAlloc" ascii
    $crt = "CreateRemoteThread" ascii
  condition:
    __smallish and GO_Runtime_Fingerprint and ( $sc1 or $sc2 ) and ( $dl1 or $dl2 or $va or $crt )
}

/* ================= B) RUST identification & behaviors ================= */

/* B1: Надёжная идентификация Rust */
rule RUST_Runtime_Fingerprint
{
  meta: category="rust" severity="info"
  strings:
    $r0 = ".rustc" ascii
    $r1 = "rust_eh_personality" ascii
    $r2 = "core::" ascii
    $r3 = "std::" ascii
    $r4 = "panic" ascii
    $r5 = "alloc::" ascii
  condition:
    __smallish and ( $r0 or 2 of ($r1,$r2,$r3,$r4,$r5) )
}

/* B2: Rust loader/exfil: reqwest/hyper + serde + Base64 + Command */
rule RUST_Loader_HTTP_Base64_Command
{
  meta: category="rust-loader" severity="high"
  strings:
    $rq = "reqwest::" ascii
    $hy = "hyper::" ascii
    $ur = "ureq::" ascii
    $sd = "serde_json::" ascii
    $b6 = "base64::decode" ascii
    $cm = "std::process::Command" ascii
    $tk = "tokio::" ascii
  condition:
    __smallish and RUST_Runtime_Fingerprint and
    ( ($rq or $hy or $ur) and ($sd or $b6) and $cm ) or ( ($rq or $hy) and $tk and $cm )
}

/* B3: Rust Windows-примитивы (в PE) для инжекта/крэда */
rule RUST_WinAPI_Memory_Primitives
{
  meta: category="rust-injection" severity="medium"
  condition:
    __is_pe and __smallish and RUST_Runtime_Fingerprint and
    (
      pe.imports("kernel32.dll","VirtualAlloc") or
      pe.imports("kernel32.dll","WriteProcessMemory") or
      pe.imports("kernel32.dll","CreateRemoteThread") or
      pe.imports("advapi32.dll","CryptAcquireContextA")
    )
}

/* ================= C) Static linking / packers (cross-platform) ================= */

/* C1: ELF статлинк (musl/static) + отсутствие интерпретера */
rule ELF_Static_MUSL_or_NoInterp
{
  meta: category="static" severity="medium"
  strings:
    $mu1 = "musl" ascii
    $mu2 = "/lib/ld-musl-" ascii
  condition:
    __is_elf and __smallish and
    ( $mu1 or $mu2 or
      not for any i in (0 .. elf.number_of_sections - 1): ( elf.sections[i].name == ".interp" )
    )
}

/* C2: UPX/похожая упаковка */
rule Generic_UPX_Packer
{
  meta: category="packer" severity="medium"
  strings:
    $u0 = "UPX!" ascii
    $u1 = ".upx0" ascii nocase
    $u2 = ".upx1" ascii nocase
  condition:
    __smallish and 1 of ($u0,$u1,$u2)
}

/* C3: Self-unpack/runtime RWX (универсально) */
rule Any_Runtime_RWX_or_AllocExec
{
  meta: category="memory" severity="high"
  strings:
    $mp = "mprotect" ascii
    $mm = "mmap" ascii
    $dl = "dlsym" ascii
  condition:
    (__is_elf and __smallish and (
      for any i in (0 .. elf.number_of_sections - 1):
        ( (elf.sections[i].flags & 0x1) == 0x1 and (elf.sections[i].flags & 0x4) == 0x4 )
      or ( elf.imports("mprotect") and ( elf.imports("mmap") or $mm ) and ( elf.imports("dlsym") or $dl ) )
    ))
    or
    (__is_pe and __smallish and
      for any i in (0 .. pe.number_of_sections - 1):
        ( (pe.sections[i].characteristics & 0xA0000000) == 0xA0000000 )
    )
    or
    (__is_macho and __smallish and
      for any i in (0 .. macho.nsegments - 1):
        ( (macho.segments[i].initprot & 0x2) == 0x2 and (macho.segments[i].initprot & 0x4) == 0x4 )
    )
}

/* ================= D) Exfil/C2 endpoints (универсальные) ================= */

rule Cross_C2_Webhooks_Common
{
  meta: category="exfil" severity="high"
  strings:
    $dc = /https?:\/\/(discord(app)?\.com\/api\/webhooks)/ nocase
    $tg = /https?:\/\/api\.telegram\.org\/bot/ nocase
    $pb = /https?:\/\/pastebin\.com\/(api|raw)/ nocase
    $gs = /https?:\/\/api\.github\.com\/gists/ nocase
  condition:
    __smallish and ( $dc or $tg or $pb or $gs )
}

/* ================= E) High-Confidence COMBOS (низкий FP) ================= */

/* E1: Go — сеть+обфускация+исполнение */
rule GO_HC_Net_Base64_Exec
{
  meta: category="combo" severity="critical"
  condition:
    GO_Loader_HTTP_Base64_Exec and ( Any_Runtime_RWX_or_AllocExec or Cross_C2_Webhooks_Common )
}

/* E2: Rust — reqwest/hyper + Command + Base64/serde */
rule RUST_HC_HTTP_Command
{
  meta: category="combo" severity="critical"
  condition:
    RUST_Loader_HTTP_Base64_Command and ( Any_Runtime_RWX_or_AllocExec or Cross_C2_Webhooks_Common )
}

/* E3: ELF статлинк + RWX/alloc-exec + сеть (вероятный packed dropper) */
rule ELF_HC_Static_Packed_Loader
{
  meta: category="combo" severity="high"
  condition:
    ELF_Static_MUSL_or_NoInterp and Any_Runtime_RWX_or_AllocExec and GO_Runtime_Fingerprint or
    ELF_Static_MUSL_or_NoInterp and Any_Runtime_RWX_or_AllocExec and RUST_Runtime_Fingerprint
}
