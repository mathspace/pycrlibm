# pycrlibm threat model

## 1. Overview

pycrlibm is a CPython extension binding vendored CRlibm scalar mathematical functions. Each wrapper converts one Python argument to a C `double`, calls a fixed native function and returns a Python floating-point value (`ext/crlibmmodule.c:9`). The README describes correctly rounded elementary functions; that numerical guarantee is an upstream claim, not independent verification of every compiler/platform combination (`README.rst:22`). The library does not parse an expression language or choose a native function pointer from input text.

Normal use is importing `crlibm` into a Python process and calling a named rounding variant. Source installation additionally compiles/links native code. Windows has a distinct MSYS2/MinGW build path and may consume a binary wheel instead. Historical Appveyor configuration includes tag-triggered wheel publication; that release authority is separate from runtime numeric calls (`README.rst:46`, `appveyor.yml:78`).

| Component | Responsibility | Evidence |
| --- | --- | --- |
| CPython wrapper | Argument conversion, fixed native call, Python result | `ext/crlibmmodule.c:9` |
| CRlibm implementation | Native numerical functions and platform FPU initialization | `crlibm/crlibm_private.c:58` |
| Extension builder | Link against local CRlibm; invoke make on initial build failure | `setup.py:101`, `setup.py:153` |
| Windows compiler adapter | Discover Python DLL and produce MSYS2 build arguments | `setup.py:72` |
| Release uploader | Distutils upload options with environment overrides | `setup.py:114` |

| Workflow | Configuration chain | Effective resource | Recipients/control | Evidence |
| --- | --- | --- | --- | --- |
| Runtime calculation | Exported wrapper → `PyArg_ParseTuple` format `d` → native function | One C double in/out in caller process | CPython conversion and fixed function target; no process isolation | `ext/crlibmmodule.c:9` |
| Module import | `crlibm_init` → platform feature macros | Supported non-BSD x86 paths set double precision/round-to-nearest FPU control; other branches differ | Importing execution context; platform compile-time conditions | `ext/crlibmmodule.c:125`, `crlibm/crlibm_private.c:58` |
| POSIX source build | Initial link failure → `make crlibm-notest` → configure prefix | `<build-cwd>/build/crlibm/include` and `lib`, linked as `crlibm` | Build tools and extension; trusted workspace/toolchain | `setup.py:108`, `setup.py:157`, `Makefile:25` |
| Windows source build | MSYS2 compiler → Python DLL lookup → `make msys2` | Same absolute CRlibm prefix, plus `build/crlibm/lib/&lt;Python-DLL-basename&gt;.a` | `gendef`, `dlltool`, compiler; OS/toolchain discovery controls | `setup.py:72`, `Makefile:14` |
| CI publication | Tagged build → wheel upload → inherited distutils options → `PYPI_*` attributes | Built wheels; effective registry from resulting upload configuration; password is CI `PYPI_PASSWORD` reference | Registry and release process; external CI secret protections | `appveyor.yml:78`, `setup.py:120` |

Build paths use the current build workspace. A failed initial extension build triggers native make and a second attempt; this is not an isolated system library service. The fallback selects a target that omits tests, whereas explicit `make crlibm` runs checks before installation (`setup.py:108`, `Makefile:3`, `Makefile:6`).

## 2. Threat Model, Trust Boundaries, and Assumptions

The assets are host process memory safety and availability, numerical-result integrity, compatibility of floating-point state, native artifact provenance, and release credentials. Numeric callers can choose values accepted by CPython conversion, including exceptional mathematical domains where supported. They do not thereby choose file paths, compiler commands, upload destinations or release credentials.

The wrapper’s narrow scalar interface is a useful constraint: input is converted before entering a fixed native function, and the result is returned directly as a Python value (`ext/crlibmmodule.c:12`). It is not evidence that every native implementation is memory-safe or that numerical exceptions match a particular application’s policy. Applications must define handling for infinities, NaNs and out-of-domain results, and decide whether a returned number can safely drive a consequential decision. No such application is established here.

Import has a separate state effect. The wrapper invokes `crlibm_init`; on certain compiled x86 configurations the native initializer saves and changes FPU control state. The wrapper does not retain that old state or expose a matching restoration lifecycle (`ext/crlibmmodule.c:125`, `crlibm/crlibm_private.c:65`, `crlibm/crlibm_private.c:102`). BSD-configured branches behave differently. A host that mixes numerical libraries or manages threads must establish the relevant platform/initialization invariant rather than assuming import has no floating-point-state consequences. This model does not claim an observed numerical failure.

Build inputs carry substantially greater authority than scalar values. `setup.py` executes Python build logic, compilers process local native sources, and the MSYS2 path discovers a Python DLL before generating an import library. Windows lookup includes a 32-bit `syswow64` substitution; the Makefile enables SSE2 and selects BSD-style CRlibm configuration (`setup.py:72`, `Makefile:16`). Caller or CI ownership of build directories and executable resolution therefore matters. A hostile installed extension is already native code in the process; that is not a new exploit caused by a numeric call.

Publication has a concrete configuration discrepancy. The uploader documents environment values overriding `.pypirc`, and sets attributes by stripping `PYPI_` and lowercasing the remainder. Appveyor’s repository-variable name contains a trailing apostrophe, so that declaration does not name the normal `repository` attribute (`setup.py:114`, `setup.py:123`, `appveyor.yml:12`). The effective registry cannot be inferred from the intended override; inherited distutils configuration remains material. This observation does not establish credential theft or a wrong actual destination.

The snapshot contains historical source and CI paths. Actual CI permissions, secret availability on different event types, registry configuration, toolchain compatibility and installed wheel provenance were not inspected externally. Correct-rounding claims should not be expanded into claims of sandboxing, thread isolation or universal host compatibility.

## 3. Attack Surface, Mitigations, and Attacker Stories

These are hypotheses for focused validation, not confirmed vulnerabilities. Severity depends on the actual host or release boundary, not the fact that C code or credentials exist.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High, conditional | Chosen scalar triggers a native fault crossing process integrity/availability | A reachable defective CRlibm path and host acceptance of attacker values | Native memory impact or shared worker outage, only if demonstrated | Fixed scalar conversion and fixed function targets | Validate actual native path/platform; maintain trusted builds and appropriate host isolation | `ext/crlibmmodule.c:9` |
| Context-dependent | FPU initialization violates a host numerical-state invariant | Affected compile-time platform, host state expectations and consequential later calculation | Incorrect calculation in the affected execution context | Platform-specific initialization logic; some branches are no-ops | Establish initialization/thread policy and verify numerical coexistence on supported builds | `ext/crlibmmodule.c:125`, `crlibm/crlibm_private.c:58` |
| High, conditional | Lower-trust build input becomes native code shipped to consumers | Attacker can influence source/toolchain/workspace below maintainer authority | Extension consumers execute modified native code | Explicit local sources, include/library paths and compiler selection | Control build inputs and verify artifact provenance | `setup.py:153`, `Makefile:25` |
| High, conditional | Release configuration/credential handling sends credentials or artifacts to an unintended registry | Effective inherited configuration or reachable CI input changes destination | Credential exposure or unauthorized distribution | Tag condition and authenticated upload; actual CI controls external | Verify the consumed repository attribute/account and exact artifact before publication | `setup.py:123`, `appveyor.yml:12`, `appveyor.yml:78` |

A numerical edge case must be tied to an observable wrong result, fault or downstream invariant; ordinary floating-point behavior is not automatically a security issue. Likewise, a malformed configuration key is actionable evidence of configuration ambiguity, but exploitability requires the resulting recipient and attacker control to be established. Runtime scalar input and CI publication authority should never be collapsed into one attack story.

## 4. Severity Calibration (Critical, High, Medium, Low)

**Critical:** Requires demonstrated broad or catastrophic reach, such as compromised native artifacts distributed through a trusted release channel to many privileged consumers. Native implementation language or an encrypted CI secret reference alone does not justify this rating.

**High:** A reproducible input-driven native memory-safety violation, material shared-service outage, or actual release-credential compromise can qualify. A local numeric error with no sensitive consequence and maintainer-authorized publication are counterexamples.

**Medium:** A bounded worker disruption, or an established numerical-state interaction that materially affects another operation, may qualify. The relevant platform and host invariant must be specified; import-time FPU modification by itself is architecture, not a proven vulnerability.

**Low:** Recoverable conversion errors, limited installation problems or inconsequential numeric/diagnostic differences. Historical dependency versions and unavailable old CI endpoints are maintenance context unless connected to a concrete security failure.

This review maps runtime, native build and publication boundaries without running the application or auditing every numerical algorithm. Host exposure, platform behavior and effective release configuration remain the principal external prerequisites.

---

Repository: https://github.com/mathspace/pycrlibm  
Version: `c82c2118354df3672b924be37902903a38eca45c`
