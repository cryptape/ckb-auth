use anyhow::{anyhow, Error};
use ckb_auth_rs::AlgorithmType;
use ckb_vm::cost_model::estimate_cycles;
use ckb_vm::registers::{A0, A7};
use ckb_vm::{Bytes, Memory, Register, SupportMachine, Syscalls};
use hex::encode;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref AUTH_CODE: Bytes = Bytes::from(&include_bytes!("../../../build/auth")[..]);
}

pub struct DebugSyscall {}
impl<Mac: SupportMachine> Syscalls<Mac> for DebugSyscall {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), ckb_vm::error::Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, ckb_vm::error::Error> {
        let code = &machine.registers()[A7];
        if code.to_i32() != 2177 {
            return Ok(false);
        }

        let mut addr = machine.registers()[A0].to_u64();
        let mut buffer = Vec::new();

        loop {
            let byte = machine
                .memory_mut()
                .load8(&Mac::REG::from_u64(addr))?
                .to_u8();
            if byte == 0 {
                break;
            }
            buffer.push(byte);
            addr += 1;
        }

        let s = String::from_utf8(buffer).unwrap();
        println!("{:?}", s);

        Ok(true)
    }
}

pub fn run_auth_exec(
    algorithm_id: AlgorithmType,
    pubkey_hash: &[u8],
    message: &[u8],
    sign: &[u8],
) -> Result<(), Error> {
    let args_algorithm_id = format!("{:02X?}", algorithm_id as u8);
    let args_sign = encode(sign);
    let args_msg = encode(message);
    let args_pubkey_hash = encode(pubkey_hash);

    let asm_core = ckb_vm::machine::asm::AsmCoreMachine::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
        ckb_vm::machine::VERSION1,
        u64::MAX,
    );
    let core = ckb_vm::DefaultMachineBuilder::new(asm_core)
        .instruction_cycle_func(Box::new(estimate_cycles))
        .syscall(Box::new(DebugSyscall {}))
        .build();
    let mut machine = ckb_vm::machine::asm::AsmMachine::new(core);
    machine
        .load_program(
            &AUTH_CODE,
            &[
                Bytes::copy_from_slice(args_algorithm_id.as_bytes()),
                Bytes::copy_from_slice(args_sign.as_bytes()),
                Bytes::copy_from_slice(args_msg.as_bytes()),
                Bytes::copy_from_slice(args_pubkey_hash.as_bytes()),
            ],
        )
        .expect("load auth_code failed");
    let exit = machine.run().expect("run failed");

    if exit != 0 {
        Err(anyhow!("verify failed, return code: {}", exit))
    } else {
        Ok(())
    }
}
