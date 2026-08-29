;; JOCKY WebAssembly Module: Case INC-BYOVD-001
(module
  (memory (export "memory") 1 4)
  (import "env" "jocky_host_host_drivers" (func $imp_0 (param i32 i32) (result i32)))
  (import "env" "jocky_host_export_evidence" (func $imp_1 (param i32 i32) (result i32)))
  (func (export "run_case") (result i32)
    (local $status i32)
    i32.const 1024
    i32.const 4096
    call $imp_0
    local.set $status
    i32.const 1024
    i32.const 4096
    call $imp_1
    local.set $status
    local.get $status
  )
)
