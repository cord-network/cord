// This file is part of CORD – https://cord.network

// Copyright (C) Dhiway Networks Pvt. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

// CORD is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// CORD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with CORD. If not, see <https://www.gnu.org/licenses/>.

use assert_cmd::cargo::cargo_bin;
use std::{process::Command, result::Result};
use tempfile::tempdir;

static RUNTIMES: &[&str] = &["base", "flow"];

/// `benchmark overhead` works for all dev runtimes.
#[test]
fn benchmark_overhead_works() {
	for runtime in RUNTIMES {
		let runtime = format!("dev-braid-{}", runtime);
		assert!(benchmark_overhead(&runtime).is_ok());
	}
}

fn benchmark_overhead(runtime: &str) -> Result<(), String> {
	let tmp_dir = tempdir().expect("could not create a temp dir");
	let base_path = tmp_dir.path();

	// Invoke `benchmark overhead` with all options to make sure that they are valid.
	let status = Command::new(cargo_bin("cord"))
		.args(["benchmark", "overhead", "--chain", &runtime])
		.arg("-d")
		.arg(base_path)
		.arg("--weight-path")
		.arg(base_path)
		.args(["--warmup", "5", "--repeat", "5"])
		.args(["--add", "100", "--mul", "1.2", "--metric", "p75"])
		// Only put 5 extrinsics into the block otherwise it takes forever to build it
		// especially for a non-release builds.
		.args(["--max-ext-per-block", "5"])
		.status()
		.map_err(|e| format!("command failed: {:?}", e))?;

	if !status.success() {
		return Err("Command failed".into());
	}

	// Weight files have been created.
	assert!(base_path.join("block_weights.rs").exists());
	assert!(base_path.join("extrinsic_weights.rs").exists());
	Ok(())
}
