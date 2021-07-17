#![warn(rust_2018_idioms)]
#![allow(unused_macros)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
mod macros;

#[macro_use]
extern crate log;

pub mod arch;
pub mod consts;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux as os;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos as os;
pub mod paging;
#[cfg(target_os = "linux")]
pub mod shared_queue;
pub mod vm;

pub use arch::*;
use core_affinity::CoreId;
use std::hint;
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use vm::Vm;

use crate::vm::VirtualCPU;

/// Creates a uhyve vm and runs the binary given by `path` in it.
/// Blocks until the VM has finished execution.
pub fn uhyve_run(
	path: PathBuf,
	vm_params: &vm::Parameter<'_>,
	cpu_affinity: Option<Vec<core_affinity::CoreId>>,
) -> i32 {
	// create and initialize the VM
	let vm = Arc::new({
		let mut vm = vm::create_vm(path, vm_params)
			.expect("Unable to create VM! Is the hypervisor interface (e.g. KVM) activated?");
		unsafe {
			vm.load_kernel().expect("Unabled to load the kernel");
		}
		vm
	});

	// For communication of the exit code from one vcpu to this thread as return
	// value.
	let (exit_tx, exit_rx) = channel();

	(0..vm.num_cpus()).for_each(|tid| {
		let vm = vm.clone();
		let exit_tx = exit_tx.clone();

		let local_cpu_affinity: Option<CoreId> = match &cpu_affinity {
			Some(vec) => vec.get(tid as usize).cloned(),
			None => None,
		};

		let gdb_port = vm_params.gdbport.unwrap() as u16;

		// create thread for each CPU
		thread::spawn(move || {
			debug!("Create thread for CPU {}", tid);
			match local_cpu_affinity {
				Some(core_id) => {
					debug!("Trying to pin thread {} to CPU {}", tid, core_id.id);
					core_affinity::set_for_current(core_id); // This does not return an error if it fails :(
				}
				None => debug!("No affinity specified, not binding thread"),
			}

			let mut cpu = vm.create_cpu(tid).unwrap();
			cpu.init(vm.get_entry_point()).unwrap();

			// only one core is able to enter startup code
			// => the wait for the predecessor core
			while tid != vm.cpu_online() {
				hint::spin_loop();
			}

			let connection = wait_for_gdb_connection(gdb_port).unwrap();

			let mut debugger = gdbstub::GdbStub::new(connection);

			let res = debugger.run(&mut cpu);

			dbg!(res.unwrap());
			exit_tx.send(0).unwrap();

			// jump into the VM and execute code of the guest
			// let result = cpu.run();
			// match result {
			// 	Err(x) => {
			// 		error!("CPU {} crashes! {:?}", tid, x);
			// 	}
			// 	Ok(exit_code) => {
			// 		exit_tx.send(exit_code).unwrap();
			// 	}
			// }
		});
	});

	// This is a semi-bad design. We don't wait for the other cpu's threads to
	// finish, but as soon as one cpu sends an exit code, we return it and
	// ignore the remaining running threads. A better design would be to force
	// the VCPUs externally to stop, so that the other threads don't block and
	// can be terminated correctly.
	exit_rx.recv().unwrap()
}

fn wait_for_gdb_connection(port: u16) -> io::Result<TcpStream> {
	let sockaddr = format!("localhost:{}", port);
	eprintln!("Waiting for a GDB connection on {:?}...", sockaddr);
	let sock = TcpListener::bind(sockaddr)?;
	let (stream, addr) = sock.accept()?;

	// Blocks until a GDB client connects via TCP.
	// i.e: Running `target remote localhost:<port>` from the GDB prompt.

	eprintln!("Debugger connected from {}", addr);
	Ok(stream) // `TcpStream` implements `gdbstub::Connection`
}
