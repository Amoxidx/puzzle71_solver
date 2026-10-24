//! Actual-Metal field squares against the CPU reduction.
//!
//! The diagnostic kernel is appended here. It is not part of the production shader.

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandBufferStatus, MTLCommandEncoder, MTLCommandQueue,
    MTLCompileOptions, MTLComputeCommandEncoder, MTLComputePipelineState,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLLibrary, MTLResourceOptions, MTLSize,
};
use puzzle71_solver::crypto::u256::{SECP256K1_P, U256};
use puzzle71_solver::metal_engine::metal_solver::{METAL_SHADER_SOURCE, MslU256};
use std::mem;
use std::ptr::NonNull;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}

const DIAGNOSTIC_KERNEL: &str = r#"

kernel void diagnostic_field_square(
    device const U256* inputs [[buffer(0)]],
    device U256* outputs [[buffer(1)]],
    uint tid [[thread_position_in_grid]])
{
    U256 input = inputs[tid];
    outputs[tid] = u256_sqr(input);
}

kernel void diagnostic_field_inverse(
    device const U256* inputs [[buffer(0)]],
    device U256* outputs [[buffer(1)]],
    uint tid [[thread_position_in_grid]])
{
    U256 input = inputs[tid];
    outputs[tid] = u256_inv(input);
}
"#;

fn canonical_sub(delta: u64) -> U256 {
    let (value, borrow) = SECP256K1_P.sub_borrow(&U256::from_u64(delta));
    assert_eq!(borrow, 0, "p - {delta} must not borrow out of the field");
    assert!(
        !value.gte(&SECP256K1_P),
        "p - {delta} must be a canonical field element"
    );
    value
}

fn from_msl(value: &MslU256) -> U256 {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = value.d[i * 2] as u64 | ((value.d[i * 2 + 1] as u64) << 32);
    }
    U256(limbs)
}

fn squares_on_gpu(inputs: &[U256]) -> Vec<U256> {
    field_on_gpu(inputs, "diagnostic_field_square")
}

fn field_on_gpu(inputs: &[U256], kernel_name: &str) -> Vec<U256> {
    assert!(
        !inputs.is_empty(),
        "diagnostic dispatch needs at least one input"
    );
    assert!(
        !METAL_SHADER_SOURCE.contains("diagnostic_field_square"),
        "diagnostic kernel must be appended by the test, not shipped in kernel.metal"
    );

    let device = MTLCreateSystemDefaultDevice()
        .expect("Metal device is required; a missing device is a test failure, not a skip");
    let queue = device
        .newCommandQueue()
        .expect("Metal command queue is required");

    let source = format!("{METAL_SHADER_SOURCE}\n{DIAGNOSTIC_KERNEL}");
    let options = MTLCompileOptions::new();
    let library = device
        .newLibraryWithSource_options_error(&NSString::from_str(&source), Some(&options))
        .expect("diagnostic shader must compile against the production field arithmetic");
    let function = library
        .newFunctionWithName(&NSString::from_str(kernel_name))
        .expect("appended diagnostic kernel must be present");
    let pipeline = device
        .newComputePipelineStateWithFunction_error(&function)
        .expect("diagnostic pipeline must build");

    let msl_inputs: Vec<MslU256> = inputs.iter().map(MslU256::from).collect();
    let msl_outputs = vec![MslU256 { d: [0; 8] }; inputs.len()];
    let input_bytes = inputs.len() * mem::size_of::<MslU256>();

    // SAFETY: both slices are non-empty, live for this call, and the byte lengths match them.
    // Metal copies the bytes into shared buffers before the call returns.
    let input_buffer = unsafe {
        device.newBufferWithBytes_length_options(
            NonNull::new(msl_inputs.as_ptr() as *mut _).expect("non-empty inputs"),
            input_bytes,
            MTLResourceOptions::StorageModeShared,
        )
    }
    .expect("input buffer must allocate");
    let output_buffer = unsafe {
        device.newBufferWithBytes_length_options(
            NonNull::new(msl_outputs.as_ptr() as *mut _).expect("non-empty outputs"),
            input_bytes,
            MTLResourceOptions::StorageModeShared,
        )
    }
    .expect("output buffer must allocate");

    let command_buffer = queue.commandBuffer().expect("command buffer must allocate");
    let encoder = command_buffer
        .computeCommandEncoder()
        .expect("compute encoder must allocate");
    encoder.setComputePipelineState(&pipeline);
    // SAFETY: both buffers use the shader's U256 layout, offset 0 is in range, and the retained
    // buffers outlive waitUntilCompleted below.
    unsafe {
        encoder.setBuffer_offset_atIndex(Some(&input_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(&output_buffer), 0, 1);
    }

    let threadgroup = pipeline
        .maxTotalThreadsPerThreadgroup()
        .min(inputs.len())
        .max(1);
    encoder.dispatchThreads_threadsPerThreadgroup(
        MTLSize {
            width: inputs.len(),
            height: 1,
            depth: 1,
        },
        MTLSize {
            width: threadgroup,
            height: 1,
            depth: 1,
        },
    );
    encoder.endEncoding();
    command_buffer.commit();
    command_buffer.waitUntilCompleted();
    assert_eq!(
        command_buffer.status(),
        MTLCommandBufferStatus::Completed,
        "diagnostic command buffer failed: {:?} ({:?})",
        command_buffer.status(),
        command_buffer.error()
    );

    // SAFETY: the shared output buffer holds exactly `inputs.len()` U256 values, Metal has
    // finished, and the allocation is aligned for that POD layout.
    let gpu = unsafe {
        std::slice::from_raw_parts(
            output_buffer.contents().cast::<MslU256>().as_ptr(),
            inputs.len(),
        )
    };
    let results: Vec<U256> = gpu.iter().map(from_msl).collect();
    // Keep the Metal objects alive until the copy above has finished.
    drop(pipeline);
    drop(library);
    drop::<Retained<ProtocolObject<dyn MTLCommandQueue>>>(queue);
    drop::<Retained<ProtocolObject<dyn MTLDevice>>>(device);
    results
}

fn assert_known_square(input: U256, expected_hex: &str, original_gpu_hex: &str) {
    let expected = U256::from_hex_str(expected_hex).expect("known square hex");
    let cpu = input.field_square();
    assert_eq!(cpu, expected, "CPU square diverged from the known residue");
    let gpu = squares_on_gpu(&[input]);
    assert_eq!(
        gpu[0], expected,
        "GPU square {gpu:?} expected {expected_hex}; the original dropped-carry fold returned {original_gpu_hex}"
    );
}

#[test]
fn metal_square_of_p_minus_one_is_one() {
    assert_known_square(canonical_sub(1), "1", "1");
}

#[test]
fn metal_square_of_p_minus_65537_is_0x100020001() {
    assert_known_square(canonical_sub(65537), "100020001", "1fc30");
}

#[test]
fn metal_square_of_p_minus_100000_is_0x2540be400() {
    assert_known_square(canonical_sub(100_000), "2540be400", "1540be02f");
}

#[test]
fn metal_squares_of_deterministic_canonical_values_match_cpu() {
    let mut inputs = vec![
        U256::ZERO,
        U256::ONE,
        U256::from_u64(2),
        U256::from_u64(977),
        U256::from_u64(65537),
        U256::from_u64(100_000),
        U256::from_u64(u32::MAX as u64),
        U256::from_u64(1u64 << 32),
        U256::from_u64(u64::MAX),
        U256::from_u128((1u128 << 64) + 977),
        U256([0x0000_0001_0000_03d1, 0, 0, 0]),
        canonical_sub(2),
        canonical_sub(3),
        canonical_sub(4_294_968_272), // Carry from extra * 977 rather than extra << 32.
    ];
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    for _ in 0..16 {
        state = state
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0x6A09_E667_F3BC_C909);
        inputs.push(U256([
            state,
            state.rotate_left(17),
            state ^ 0xA5A5_A5A5_A5A5_A5A5,
            0x0FFF_FFFF_FFFF_FFFF,
        ]));
    }
    for input in &inputs {
        assert!(
            !input.gte(&SECP256K1_P),
            "ordinary diagnostic input must be canonical"
        );
    }

    let gpu = squares_on_gpu(&inputs);
    assert_eq!(gpu.len(), inputs.len());
    for (input, got) in inputs.iter().zip(gpu.iter()) {
        assert_eq!(
            *got,
            input.field_square(),
            "GPU square of {input} diverged from the CPU reduction"
        );
    }
}

#[test]
fn metal_inverse_chain_matches_cpu_and_multiplies_back_to_one() {
    let mut inputs = vec![
        U256::ZERO,
        U256::ONE,
        U256::from_u64(2),
        U256::from_u64(977),
        canonical_sub(1),
        canonical_sub(65537),
        canonical_sub(100_000),
        canonical_sub(4_294_968_272),
    ];
    let mut state = 0x4c1f_f03b_ba9d_7147u64;
    for _ in 0..32 {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *limb = state;
        }
        let mut value = U256(limbs);
        if value.gte(&SECP256K1_P) {
            value = value.sub_borrow(&SECP256K1_P).0;
        }
        inputs.push(value);
    }
    let inverses = field_on_gpu(&inputs, "diagnostic_field_inverse");
    for (input, inverse) in inputs.iter().zip(inverses) {
        assert_eq!(inverse, input.field_inv(), "inverse mismatch for {input}");
        assert_eq!(
            input.field_mul(&inverse),
            if input.is_zero() {
                U256::ZERO
            } else {
                U256::ONE
            }
        );
    }
}
