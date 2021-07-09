mod regs;

use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::StopReason;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::GdbInterrupt;
use gdbstub::target::ext::base::ResumeAction;
use gdbstub::target::Target;
use gdbstub::target::TargetError;
use gdbstub::target::TargetResult;
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::kvm_guest_debug_arch;
use kvm_bindings::KVM_GUESTDBG_ENABLE;
use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;
use kvm_bindings::KVM_GUESTDBG_USE_SW_BP;
use std::convert::TryInto;
use std::slice;

use crate::linux::vcpu::UhyveCPU;
use crate::vm::VcpuStopReason;
use crate::vm::VirtualCPU;

use super::HypervisorError;

impl Target for UhyveCPU {
	type Arch = gdbstub_arch::x86::X86_64_SSE;
	type Error = HypervisorError;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
		BaseOps::SingleThread(self)
	}
}

impl SingleThreadOps for UhyveCPU {
	fn resume(
		&mut self,
		action: ResumeAction,
		gdb_interrupt: GdbInterrupt<'_>,
	) -> Result<StopReason<u64>, Self::Error> {
		loop {
			let debug_struct = kvm_guest_debug {
				// Configure the vcpu so that a KVM_DEBUG_EXIT would be generated
				// when encountering a software breakpoint during execution
				control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_SINGLESTEP,
				pad: 0,
				// Reset all x86-specific debug registers
				arch: kvm_guest_debug_arch {
					debugreg: [0, 0, 0, 0, 0, 0, 0, 0],
				},
			};
			self.get_vcpu().set_guest_debug(&debug_struct).unwrap();

			match self.r#continue()? {
				VcpuStopReason::Debug => return Ok(StopReason::DoneStep),
				VcpuStopReason::Exit(_) => todo!(),
			}
		}
	}

	fn read_registers(&mut self, regs: &mut X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::read(self.get_vcpu(), regs)
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn write_registers(&mut self, regs: &X86_64CoreRegs) -> TargetResult<(), Self> {
		regs::write(regs, self.get_vcpu())
			.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))
	}

	fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<(), Self> {
		let phys = self.virt_to_phys(start_addr.try_into().unwrap());
		let host = self.host_address(phys);

		let src = unsafe { slice::from_raw_parts(host as *mut u8, data.len()) };
		data.copy_from_slice(src);

		Ok(())
	}

	fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
		let phys = self.virt_to_phys(start_addr.try_into().unwrap());
		let host = self.host_address(phys);

		let mem = unsafe { slice::from_raw_parts_mut(host as *mut u8, data.len()) };
		mem.copy_from_slice(data);

		Ok(())
	}
}
