mod regs;

use gdbstub::target::ext::base::singlethread::SingleThreadOps;
use gdbstub::target::ext::base::singlethread::StopReason;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::GdbInterrupt;
use gdbstub::target::ext::base::ResumeAction;
use gdbstub::target::ext::breakpoints::Breakpoints;
use gdbstub::target::ext::breakpoints::BreakpointsOps;
use gdbstub::target::ext::breakpoints::HwBreakpoint;
use gdbstub::target::ext::breakpoints::HwBreakpointOps;
use gdbstub::target::ext::breakpoints::HwWatchpointOps;
use gdbstub::target::ext::breakpoints::SwBreakpointOps;
use gdbstub::target::Target;
use gdbstub::target::TargetError;
use gdbstub::target::TargetResult;
use gdbstub_arch::x86::reg::X86_64CoreRegs;
use kvm_bindings::kvm_guest_debug;
use kvm_bindings::kvm_guest_debug_arch;
use kvm_bindings::KVM_GUESTDBG_ENABLE;
use kvm_bindings::KVM_GUESTDBG_SINGLESTEP;
use kvm_bindings::KVM_GUESTDBG_USE_HW_BP;
use kvm_bindings::KVM_GUESTDBG_USE_SW_BP;
use std::convert::TryInto;
use std::slice;
use x86_64::VirtAddr;

use crate::linux::vcpu::UhyveCPU;
use crate::vm::VcpuStopReason;
use crate::vm::VirtualCPU;
use crate::x86_64::registers::debug;
use crate::x86_64::registers::debug::DebugRegisters;

use super::HypervisorError;

impl Target for UhyveCPU {
	type Arch = gdbstub_arch::x86::X86_64_SSE;
	type Error = HypervisorError;

	// --------------- IMPORTANT NOTE ---------------
	// Always remember to annotate IDET enable methods with `inline(always)`!
	// Without this annotation, LLVM might fail to dead-code-eliminate nested IDET
	// implementations, resulting in unnecessary binary bloat.

	#[inline(always)]
	fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
		BaseOps::SingleThread(self)
	}

	#[inline(always)]
	fn breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
		Some(self)
	}
}

impl Breakpoints for UhyveCPU {
	fn sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
		None
	}

	fn hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
		Some(self)
	}

	fn hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
		None
	}
}

impl UhyveCPU {
	fn apply_guest_debug(&mut self, step: bool) -> Result<(), kvm_ioctls::Error> {
		let debugreg = DebugRegisters::from(self.hw_breakpoints).0;
		let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_USE_HW_BP;
		if step {
			control |= KVM_GUESTDBG_SINGLESTEP;
		}
		let debug_struct = kvm_guest_debug {
			control,
			pad: 0,
			arch: kvm_guest_debug_arch { debugreg },
		};
		self.get_vcpu().set_guest_debug(&debug_struct)
	}
}

impl HwBreakpoint for UhyveCPU {
	fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
		if let Some(hw_breakpoint) = self
			.hw_breakpoints
			.iter_mut()
			.find(|hw_breakpoint| hw_breakpoint.is_none())
		{
			hw_breakpoint.insert(debug::HwBreakpoint {
				addr: VirtAddr::new(addr),
				level: debug::HwBreakpointLevel::Global,
				condition: debug::HwBreakpointCondition::InstructionExecution,
			});

			self.apply_guest_debug(false)
				.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))?;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
		if let Some(hw_breakpoint) = self.hw_breakpoints.iter_mut().find(|hw_breakpoint| {
			hw_breakpoint
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64() == addr)
				.unwrap_or(false)
		}) {
			hw_breakpoint.take();

			self.apply_guest_debug(false)
				.map_err(|error| TargetError::Errno(error.errno().try_into().unwrap()))?;
			Ok(true)
		} else {
			Ok(false)
		}
	}
}

impl SingleThreadOps for UhyveCPU {
	fn resume(
		&mut self,
		action: ResumeAction,
		gdb_interrupt: GdbInterrupt<'_>,
	) -> Result<StopReason<u64>, Self::Error> {
		match action {
			ResumeAction::Continue | ResumeAction::ContinueWithSignal(_) => {
				match self.r#continue()? {
					VcpuStopReason::Debug => Ok(StopReason::HwBreak),
					VcpuStopReason::Exit(code) => {
						let status = if code == 0 { 0 } else { 1 };
						Ok(StopReason::Exited(status))
					}
				}
			}
			ResumeAction::Step | ResumeAction::StepWithSignal(_) => {
				self.apply_guest_debug(true)?;
				match self.r#continue()? {
					VcpuStopReason::Debug => Ok(StopReason::DoneStep),
					VcpuStopReason::Exit(code) => {
						let status = if code == 0 { 0 } else { 1 };
						Ok(StopReason::Exited(status))
					}
				}
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
