//! Independent per-key HASH160 and production-search regressions for batch conversion.
//!
//! The two diagnostic tests append entry points that call the production batch helpers;
//! they need the batch-enabled shader. The two production-search tests use the existing
//! MetalSolver API/pipeline and can also exercise the pre-batch shader unchanged.
//! Missing Metal support or a shader compilation error fails the test rather than skipping it.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandBufferStatus, MTLCommandEncoder, MTLCommandQueue,
    MTLCompileOptions, MTLComputeCommandEncoder, MTLComputePipelineState, MTLDevice, MTLLibrary,
    MTLResourceOptions, MTLSize,
};
use puzzle71_solver::crypto::u256::{SECP256K1_N, SECP256K1_P, U256};
use puzzle71_solver::metal_engine::metal_solver::{
    METAL_SHADER_SOURCE, MetalSolver, MslAffinePoint, MslU256, SearchParams,
};
use puzzle71_solver::puzzle_config::{RANGE_MAX, RANGE_MIN};
use std::mem;
use std::ptr::NonNull;

const BATCH_SIZE: usize = 16;
const HASH_WORDS: usize = 6;
const GUARD: u32 = 0xa5a5_a5a5;
const GUARD_WORDS: usize = 16;
const DIAGNOSTICS: &str = include_str!("support/batch16_diagnostics.metal");
type Pipeline = Retained<ProtocolObject<dyn MTLComputePipelineState>>;

#[repr(C)]
#[derive(Clone, Copy)]
struct MslJacobianPoint {
    x: MslU256,
    y: MslU256,
    z: MslU256,
    is_inf: bool,
    pad: [u8; 3],
}

fn independent_public(key: u128) -> PublicKey {
    let mut bytes = [0; 32];
    bytes[16..].copy_from_slice(&key.to_be_bytes());
    SecretKey::from_slice(&bytes)
        .expect("test scalar must be a valid independent secret key")
        .public_key(&Secp256k1::signing_only())
}

fn public_hash(public: &PublicKey) -> [u8; 20] {
    bitcoin::hashes::hash160::Hash::hash(&public.serialize()).to_byte_array()
}

fn independent_hash(key: u128) -> [u8; 20] {
    public_hash(&independent_public(key))
}

fn affine(public: &PublicKey, is_inf: bool) -> MslAffinePoint {
    let serialized = public.serialize_uncompressed();
    MslAffinePoint {
        x: MslU256::from(&U256::from_be_bytes(serialized[1..33].try_into().unwrap())),
        y: MslU256::from(&U256::from_be_bytes(serialized[33..65].try_into().unwrap())),
        is_inf,
        _pad: [0; 3],
    }
}

fn scaled_point(key: u128, z: U256, is_inf: bool) -> MslJacobianPoint {
    let serialized = independent_public(key).serialize_uncompressed();
    let x = U256::from_be_bytes(serialized[1..33].try_into().unwrap());
    let y = U256::from_be_bytes(serialized[33..65].try_into().unwrap());
    let z2 = z.field_square();
    let z3 = z2.field_mul(&z);
    MslJacobianPoint {
        x: MslU256::from(&x.field_mul(&z2)),
        y: MslU256::from(&y.field_mul(&z3)),
        z: MslU256::from(&z),
        is_inf,
        pad: [0; 3],
    }
}

// These POD layouts have explicit initialized padding, matching their MSL structs.
fn bytes<T>(values: &[T]) -> &[u8] {
    // SAFETY: every caller supplies initialized POD test parameters or point layouts. The
    // returned view has the slice's exact length and cannot outlive the input allocation.
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast(), mem::size_of_val(values)) }
}

fn diagnostic_pipeline(solver: &MetalSolver, name: &str) -> Pipeline {
    let source = format!("{METAL_SHADER_SOURCE}\n{DIAGNOSTICS}");
    let library = solver
        .device
        .newLibraryWithSource_options_error(
            &NSString::from_str(&source),
            Some(&MTLCompileOptions::new()),
        )
        .expect("test entry points must compile with the actual production batch helpers");
    let function = library
        .newFunctionWithName(&NSString::from_str(name))
        .expect("appended test entry point must be available");
    solver
        .device
        .newComputePipelineStateWithFunction_error(&function)
        .expect("test pipeline must build")
}

fn guarded_dispatch(
    solver: &MetalSolver,
    pipeline: &Pipeline,
    input: &[u8],
    params: &[u8],
    initial_output: &[u32],
    threads: usize,
) -> Vec<u32> {
    assert!(!input.is_empty() && !params.is_empty() && threads > 0);
    let buffer = |data: &[u8]| {
        // SAFETY: all source bytes are initialized, non-empty, live for this call, and Metal
        // copies the exact supplied byte count into a retained shared-storage buffer.
        unsafe {
            solver.device.newBufferWithBytes_length_options(
                NonNull::new(data.as_ptr() as *mut _).unwrap(),
                data.len(),
                MTLResourceOptions::StorageModeShared,
            )
        }
        .expect("shared test buffer must allocate")
    };
    let input_buffer = buffer(input);
    let params_buffer = buffer(params);
    let mut guarded = vec![GUARD; initial_output.len() + 2 * GUARD_WORDS];
    guarded[GUARD_WORDS..GUARD_WORDS + initial_output.len()].copy_from_slice(initial_output);
    let output_buffer = buffer(bytes(&guarded));
    let command = solver.queue.commandBuffer().expect("test command buffer");
    let encoder = command.computeCommandEncoder().expect("test encoder");
    encoder.setComputePipelineState(pipeline);
    // SAFETY: offsets match the entry points' POD layouts. The output starts after an aligned
    // canary region; all retained buffers stay alive through GPU completion and readback.
    unsafe {
        encoder.setBuffer_offset_atIndex(Some(&input_buffer), 0, 0);
        encoder.setBuffer_offset_atIndex(Some(&params_buffer), 0, 1);
        encoder.setBuffer_offset_atIndex(
            Some(&output_buffer),
            GUARD_WORDS * mem::size_of::<u32>(),
            2,
        );
    }
    encoder.dispatchThreads_threadsPerThreadgroup(
        MTLSize {
            width: threads,
            height: 1,
            depth: 1,
        },
        MTLSize {
            width: threads
                .min(pipeline.maxTotalThreadsPerThreadgroup())
                .min(256),
            height: 1,
            depth: 1,
        },
    );
    encoder.endEncoding();
    command.commit();
    command.waitUntilCompleted();
    assert_eq!(
        command.status(),
        MTLCommandBufferStatus::Completed,
        "GPU command failed: {:?}",
        command.error()
    );
    // SAFETY: the exact initialized u32 buffer is shared, aligned, and no GPU command is
    // running. Copying occurs while the retained output allocation is still alive.
    let output = unsafe {
        std::slice::from_raw_parts(
            output_buffer.contents().cast::<u32>().as_ptr(),
            guarded.len(),
        )
    };
    assert!(
        output[..GUARD_WORDS].iter().all(|word| *word == GUARD),
        "GPU overwrote the leading output canary"
    );
    assert!(
        output[GUARD_WORDS + initial_output.len()..]
            .iter()
            .all(|word| *word == GUARD),
        "GPU overwrote the trailing output canary"
    );
    // SAFETY: these shared input buffers remain allocated and have their original exact byte
    // lengths. The GPU completed; their read-only parameters must not have been mutated.
    for (actual_buffer, expected) in [(&input_buffer, input), (&params_buffer, params)] {
        let actual = unsafe {
            std::slice::from_raw_parts(
                actual_buffer.contents().cast::<u8>().as_ptr(),
                expected.len(),
            )
        };
        assert_eq!(
            actual, expected,
            "GPU changed a read-only input or parameter buffer"
        );
    }
    output[GUARD_WORDS..GUARD_WORDS + initial_output.len()].to_vec()
}

fn assert_hash_row(row: &[u32], expected: Option<[u8; 20]>, label: &str) {
    if let Some(expected) = expected {
        assert_eq!(row[0], 1, "finite point missing: {label}");
        let mut actual = [0; 20];
        for (index, word) in row[1..].iter().enumerate() {
            actual[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(actual, expected, "independent HASH160 mismatch: {label}");
    } else {
        assert_eq!(
            row, [0; HASH_WORDS],
            "infinity or zero-Z must not hash: {label}"
        );
    }
}

#[test]
fn batch16_every_valid_key_hash_matches_independent_libsecp() {
    let solver = MetalSolver::new().expect("actual Metal device required");
    let pipeline = diagnostic_pipeline(&solver, "test_batch16_hashes");
    let mut cases: Vec<(u128, usize, u32, usize)> = [1u32, 9, 15, 16, 17, 128, 256]
        .into_iter()
        .map(|steps| {
            let valid = if steps < 33 {
                37
            } else {
                3 * steps as usize - 7
            };
            (
                RANGE_MIN + 0x2345,
                valid.div_ceil(steps as usize) + 2,
                steps,
                valid,
            )
        })
        .collect();
    cases.extend([
        (RANGE_MIN, 3, 17, 33),
        (RANGE_MAX - 254, 4, 128, 255),
        (RANGE_MIN + (1u128 << 64) - 17, 6, 17, 67),
        (RANGE_MIN + 0x1234_5678, 66, 128, 8191),
        (RANGE_MIN + 0x1234_abcd, 19, 256, 4337),
        (0, 7, 9, 43),
        (RANGE_MIN, 3, 17, 0),
    ]);
    let mut finite = 0;
    let mut infinity = 0;
    for (start, threads, steps, valid) in cases {
        let capacity = threads * steps as usize;
        let initial_points = MetalSolver::precompute_initial_points(start, threads, steps);
        let params = SearchParams {
            target_hash160: [0; 5],
            step_count: steps,
            valid_key_count: valid as u32,
        };
        let output = guarded_dispatch(
            &solver,
            &pipeline,
            bytes(&initial_points),
            bytes(&[params]),
            &vec![GUARD; capacity * HASH_WORDS],
            threads,
        );
        for (offset, row) in output[..valid * HASH_WORDS]
            .chunks_exact(HASH_WORDS)
            .enumerate()
        {
            let key = start + offset as u128;
            let expected = if key == 0 {
                infinity += 1;
                None
            } else {
                finite += 1;
                Some(independent_hash(key))
            };
            assert_hash_row(
                row,
                expected,
                &format!("start={start:x}, steps={steps}, offset={offset}"),
            );
        }
        assert!(
            output[valid * HASH_WORDS..]
                .iter()
                .all(|word| *word == GUARD),
            "padding output touched: start={start:x}, steps={steps}, valid={valid}"
        );
    }
    assert_eq!((finite, infinity), (14_248, 1));
    eprintln!(
        "independently compared {finite} finite HASH160 rows; checked {infinity} infinity row and all capacity padding/canaries"
    );
}

#[test]
fn production_search_finds_independent_boundary_targets_and_excludes_padding() {
    let solver = MetalSolver::new().expect("actual Metal device required");
    let mut positive = 0;
    let mut negative = 0;
    for steps in [1u32, 9, 15, 16, 17, 128, 256] {
        let valid = if steps < 128 {
            37
        } else {
            2 * steps as usize + 17
        };
        let threads = valid.div_ceil(steps as usize) + 2;
        for start in [
            RANGE_MIN,
            RANGE_MAX + 1 - valid as u128,
            RANGE_MIN + (1u128 << 64) - 17,
        ] {
            let mut offsets = vec![
                0,
                15,
                16,
                17,
                31,
                32,
                valid - 1,
                steps as usize - 1,
                steps as usize,
                2 * steps as usize + 1,
            ];
            offsets.retain(|offset| *offset < valid);
            offsets.sort_unstable();
            offsets.dedup();
            for offset in offsets {
                let key = start + offset as u128;
                let found = solver
                    .dispatch_exact(start, threads, steps, valid, &independent_hash(key))
                    .expect("production positive dispatch");
                assert_eq!(
                    found.found_key,
                    Some(key),
                    "start={start:x}, steps={steps}, offset={offset}"
                );
                positive += 1;
            }
            for key in [
                start - 1,
                start + valid as u128,
                start + (threads * steps as usize - 1) as u128,
            ] {
                let found = solver
                    .dispatch_exact(start, threads, steps, valid, &independent_hash(key))
                    .expect("production excluded-target dispatch");
                assert_eq!(
                    found.found_key, None,
                    "out-of-window target={key:x}, start={start:x}, steps={steps}, valid={valid}"
                );
                negative += 1;
            }
        }
    }
    eprintln!(
        "production target controls: {positive} positive and {negative} negative dispatches; these do not enumerate every searched key"
    );
}

fn raw_search(
    solver: &MetalSolver,
    points: &[MslAffinePoint],
    steps: u32,
    valid: u32,
    target: [u8; 20],
) -> Option<(u32, u32)> {
    let mut target_words = [0; 5];
    for (index, word) in target_words.iter_mut().enumerate() {
        *word = u32::from_le_bytes(target[index * 4..index * 4 + 4].try_into().unwrap());
    }
    let params = SearchParams {
        target_hash160: target_words,
        step_count: steps,
        valid_key_count: valid,
    };
    let result = guarded_dispatch(
        solver,
        &solver.pipeline,
        bytes(points),
        bytes(&[params]),
        &[0, GUARD, GUARD],
        points.len(),
    );
    match result[0] {
        0 => {
            assert_eq!(
                &result[1..],
                &[GUARD, GUARD],
                "negative search changed result coordinates"
            );
            None
        }
        1 => Some((result[1], result[2])),
        flag => panic!("invalid found flag: {flag}"),
    }
}

#[test]
fn production_search_skips_infinity_without_losing_the_following_generator() {
    let solver = MetalSolver::new().expect("actual Metal device required");
    assert!(
        SecretKey::from_slice(&[0; 32]).is_err(),
        "scalar zero has no valid libsecp public key"
    );
    let mut fake_compressed_zero = [0; 33];
    fake_compressed_zero[0] = 2;
    let invalid_zero_hash =
        bitcoin::hashes::hash160::Hash::hash(&fake_compressed_zero).to_byte_array();
    for steps in [1u32, 9, 15, 16, 17, 128, 256] {
        let absent = solver
            .dispatch_exact(0, 3, steps, 1, &invalid_zero_hash)
            .expect("zero-scalar negative dispatch");
        assert_eq!(
            absent.found_key, None,
            "scalar-zero placeholder hashed at steps={steps}"
        );
        let generator = solver
            .dispatch_exact(0, 3, steps, 2, &independent_hash(1))
            .expect("generator after zero dispatch");
        assert_eq!(
            generator.found_key,
            Some(1),
            "following generator lost at steps={steps}"
        );
    }
    // is_inf is authoritative even when the placeholder retains ordinary nonzero coordinates.
    let placeholder = independent_public(314);
    let infinite = [affine(&placeholder, true)];
    assert_eq!(
        raw_search(&solver, &infinite, 17, 17, public_hash(&placeholder)),
        None
    );
    assert_eq!(
        raw_search(&solver, &infinite, 17, 17, independent_hash(1)),
        Some((0, 1))
    );

    // -G + G is infinity in the middle of a batch; the subsequent addition yields G again.
    let order_minus_one = SECP256K1_N.sub_borrow(&U256::ONE).0.to_be_bytes();
    let negative_generator = SecretKey::from_slice(&order_minus_one)
        .unwrap()
        .public_key(&Secp256k1::signing_only());
    let points = [affine(&negative_generator, false)];
    assert_eq!(
        raw_search(&solver, &points, 17, 2, independent_hash(1)),
        None,
        "G is padding until the third step"
    );
    assert_eq!(
        raw_search(&solver, &points, 17, 3, independent_hash(1)),
        Some((0, 2)),
        "middle infinity changed the following offset"
    );
}

#[test]
fn batch16_scaled_points_and_zero_z_or_infinity_do_not_poison_neighbors() {
    let solver = MetalSolver::new().expect("actual Metal device required");
    let pipeline = diagnostic_pipeline(&solver, "test_batch16_explicit_points");
    let mut checked = 0;
    for rotation in 0..BATCH_SIZE {
        let mut points = Vec::new();
        let mut expected = Vec::new();
        for index in 0..BATCH_SIZE {
            let kind = (index + rotation) % 8;
            let z = match kind {
                0 | 5 => U256::ONE,
                2 | 4 => U256::ZERO,
                3 => SECP256K1_P.sub_borrow(&U256::from_u64(65537)).0,
                6 => SECP256K1_P.sub_borrow(&U256::from_u64(100_000)).0,
                7 => U256::from_u64(65537),
                _ => U256::from_u64(3 + index as u64),
            };
            let is_inf = kind == 0 || kind == 4;
            let key = 1000 + index as u128;
            points.push(scaled_point(key, z, is_inf));
            expected.push(if is_inf || z.is_zero() {
                None
            } else {
                Some(independent_hash(key))
            });
        }
        for count in [0usize, 1, BATCH_SIZE - 1, BATCH_SIZE] {
            let output = guarded_dispatch(
                &solver,
                &pipeline,
                bytes(&points),
                bytes(&[count as u32]),
                &[GUARD; BATCH_SIZE * HASH_WORDS],
                4,
            );
            for (index, row) in output[..count * HASH_WORDS]
                .chunks_exact(HASH_WORDS)
                .enumerate()
            {
                assert_hash_row(
                    row,
                    expected[index],
                    &format!("rotation={rotation}, count={count}, index={index}"),
                );
                checked += 1;
            }
            assert!(
                output[count * HASH_WORDS..]
                    .iter()
                    .all(|word| *word == GUARD),
                "explicit partial-batch padding overwritten: rotation={rotation}, count={count}"
            );
        }
    }
    // Also cover a whole product with no finite factors, including a nonzero-Z flagged batch.
    for (z, is_inf) in [(U256::ZERO, false), (U256::ONE, true)] {
        let points: Vec<_> = (0..BATCH_SIZE)
            .map(|index| scaled_point(2000 + index as u128, z, is_inf))
            .collect();
        let output = guarded_dispatch(
            &solver,
            &pipeline,
            bytes(&points),
            bytes(&[BATCH_SIZE as u32]),
            &[GUARD; BATCH_SIZE * HASH_WORDS],
            4,
        );
        for row in output.chunks_exact(HASH_WORDS) {
            assert_hash_row(row, None, "entire batch has no finite points");
            checked += 1;
        }
    }
    assert_eq!(checked, 544);
    eprintln!("checked {checked} explicit Jacobian rows, plus zero-count/padding/canary guards");
}
