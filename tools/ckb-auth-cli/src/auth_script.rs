use anyhow::{anyhow, Error};
use ckb_auth_rs::AlgorithmType;
use ckb_types::core::ScriptHashType;
use ckb_vm::instructions::{extract_opcode, insts};
use ckb_vm::registers::{A0, A7};
use ckb_vm::{Bytes, Instruction, Memory, Register, SupportMachine, Syscalls};
use hex::encode;
use lazy_static::lazy_static;

const AUTH_CODE_HASH: [u8; 32] = [0; 32];
const AUTH_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;

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
pub fn instruction_cycles(i: Instruction) -> u64 {
    match extract_opcode(i) {
        // IMC
        insts::OP_JALR => 3,
        insts::OP_LD => 2,
        insts::OP_LW => 3,
        insts::OP_LH => 3,
        insts::OP_LB => 3,
        insts::OP_LWU => 3,
        insts::OP_LHU => 3,
        insts::OP_LBU => 3,
        insts::OP_SB => 3,
        insts::OP_SH => 3,
        insts::OP_SW => 3,
        insts::OP_SD => 2,
        insts::OP_BEQ => 3,
        insts::OP_BGE => 3,
        insts::OP_BGEU => 3,
        insts::OP_BLT => 3,
        insts::OP_BLTU => 3,
        insts::OP_BNE => 3,
        insts::OP_EBREAK => 500,
        insts::OP_ECALL => 500,
        insts::OP_JAL => 3,
        insts::OP_MUL => 5,
        insts::OP_MULW => 5,
        insts::OP_MULH => 5,
        insts::OP_MULHU => 5,
        insts::OP_MULHSU => 5,
        insts::OP_DIV => 32,
        insts::OP_DIVW => 32,
        insts::OP_DIVU => 32,
        insts::OP_DIVUW => 32,
        insts::OP_REM => 32,
        insts::OP_REMW => 32,
        insts::OP_REMU => 32,
        insts::OP_REMUW => 32,
        // MOP
        insts::OP_WIDE_MUL => 5,
        insts::OP_WIDE_MULU => 5,
        insts::OP_WIDE_MULSU => 5,
        insts::OP_WIDE_DIV => 32,
        insts::OP_WIDE_DIVU => 32,
        insts::OP_FAR_JUMP_REL => 3,
        insts::OP_FAR_JUMP_ABS => 3,
        _ => 1,
    }
}

pub fn run_auth_exec(
    algorithm_id: AlgorithmType,
    pubkey_hash: &[u8],
    message: &[u8],
    sign: &[u8],
) -> Result<(), Error> {
    let args = format!(
        "{}:{:02X?}:{:02X?}:{}:{}:{}",
        encode(&AUTH_CODE_HASH),
        AUTH_HASH_TYPE as u8,
        algorithm_id as u8,
        encode(sign),
        encode(message),
        encode(pubkey_hash)
    );

    let asm_core = ckb_vm::machine::asm::AsmCoreMachine::new(
        ckb_vm::ISA_IMC | ckb_vm::ISA_B | ckb_vm::ISA_MOP,
        ckb_vm::machine::VERSION1,
        u64::MAX,
    );
    let core = ckb_vm::DefaultMachineBuilder::new(asm_core)
        .instruction_cycle_func(Box::new(instruction_cycles))
        .syscall(Box::new(DebugSyscall {}))
        .build();
    let mut machine = ckb_vm::machine::asm::AsmMachine::new(core);
    machine
        .load_program(&AUTH_CODE, &[Bytes::copy_from_slice(args.as_bytes())])
        .expect("load auth_code failed");
    let exit = machine.run().expect("run failed");

    if exit != 0 {
        Err(anyhow!("verify failed, return code: {}", exit))
    } else {
        Ok(())
    }
}
