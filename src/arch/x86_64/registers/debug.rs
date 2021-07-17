//! Functions to read and write debug registers.

use x86_64::VirtAddr;

#[derive(Clone, Copy, Debug)]
pub struct HwBreakpoint {
	pub addr: VirtAddr,
	pub level: HwBreakpointLevel,
	pub condition: HwBreakpointCondition,
}

#[derive(Clone, Copy, Debug)]
pub enum HwBreakpointLevel {
	Local,
	Global,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum HwBreakpointCondition {
	InstructionExecution = 0b00,
	DataWrites = 0b01,
	IoReadsWrites = 0b10,
	DataReadsWrites = 0b11,
}

pub type HwBreakpoints = [Option<HwBreakpoint>; 4];

fn control_value(hw_breakpoints: &HwBreakpoints, general_detect_enable: bool) -> u64 {
	const GENERAL_DETECT_ENABLE_FLAG: u64 = 1 << 13;
	const GLOBAL_EXACT_BREAKPOINT_ENABLE_FLAG: u64 = 1 << 9;
	const LOCAL_EXACT_BREAKPOINT_ENABLE_FLAG: u64 = 1 << 8;

	let mut control_value =
		LOCAL_EXACT_BREAKPOINT_ENABLE_FLAG | GLOBAL_EXACT_BREAKPOINT_ENABLE_FLAG;

	if general_detect_enable {
		control_value |= GENERAL_DETECT_ENABLE_FLAG;
	}

	for (i, hw_breakpoint) in hw_breakpoints.iter().enumerate() {
		if let Some(hw_breakpoint) = hw_breakpoint {
			control_value |= 1
				<< match hw_breakpoint.level {
					HwBreakpointLevel::Local => 2 * i,
					HwBreakpointLevel::Global => 2 * i + 1,
				};

			control_value |= (hw_breakpoint.condition as u64) << 16 + 4 * i;
		}
	}

	control_value
}

pub struct DebugRegisters(pub [u64; 8]);

impl From<HwBreakpoints> for DebugRegisters {
	fn from(hw_breakpoints: HwBreakpoints) -> Self {
		let control_value = control_value(&hw_breakpoints, true);
		let debug_registers = [
			hw_breakpoints[0]
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64())
				.unwrap_or_default(),
			hw_breakpoints[1]
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64())
				.unwrap_or_default(),
			hw_breakpoints[2]
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64())
				.unwrap_or_default(),
			hw_breakpoints[3]
				.map(|hw_breakpoint| hw_breakpoint.addr.as_u64())
				.unwrap_or_default(),
			0,
			0,
			0,
			control_value,
		];
		Self(debug_registers)
	}
}
