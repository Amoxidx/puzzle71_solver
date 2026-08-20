//! High-Performance Metal GPU Solver Host with Montgomery Batch Affine Initialization.

use crate::crypto::secp256k1::{AffinePoint, JacobianPoint, scalar_mul_g};
use crate::crypto::u256::U256;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandBufferStatus, MTLCommandEncoder, MTLCommandQueue,
    MTLCompileOptions, MTLComputeCommandEncoder, MTLComputePipelineState,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLLibrary, MTLResourceOptions, MTLSize,
};
use std::mem;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}

pub const METAL_SHADER_SOURCE: &str = include_str!("kernel.metal");

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MslU256 {
    pub d: [u32; 8],
}

impl From<&U256> for MslU256 {
    fn from(u: &U256) -> Self {
        let mut d = [0u32; 8];
        for i in 0..4 {
            d[i * 2] = (u.0[i] & 0xFFFFFFFF) as u32;
            d[i * 2 + 1] = (u.0[i] >> 32) as u32;
        }
        MslU256 { d }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MslAffinePoint {
    pub x: MslU256,
    pub y: MslU256,
    pub is_inf: bool,
    pub _pad: [u8; 3], // 32-bit alignment padding
}

impl From<&AffinePoint> for MslAffinePoint {
    fn from(p: &AffinePoint) -> Self {
        MslAffinePoint {
            x: MslU256::from(&p.x),
            y: MslU256::from(&p.y),
            is_inf: p.infinity,
            _pad: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SearchParams {
    pub target_hash160: [u32; 5],
    pub step_count: u32,
    pub valid_key_count: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FoundResult {
    pub found_flag: u32,
    pub found_thread_id: u32,
    pub found_step_idx: u32,
}

pub struct MetalSolver {
    pub device: Retained<ProtocolObject<dyn MTLDevice>>,
    pub queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    pub pipeline: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    pub threads_per_threadgroup: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct DispatchOutcome {
    pub found_key: Option<u128>,
    pub gpu_duration: Duration,
}

impl MetalSolver {
    pub fn new() -> Result<Self, String> {
        let device = MTLCreateSystemDefaultDevice()
            .ok_or_else(|| "No Apple Silicon Metal device found".to_string())?;

        let queue = device
            .newCommandQueue()
            .ok_or_else(|| "Failed to create Metal command queue".to_string())?;

        let options = MTLCompileOptions::new();
        let source = NSString::from_str(METAL_SHADER_SOURCE);
        let library = device
            .newLibraryWithSource_options_error(&source, Some(&options))
            .map_err(|e| format!("Metal shader compilation error: {:?}", e))?;

        let kernel_name = NSString::from_str("puzzle71_search_kernel");
        let kernel_fn = library
            .newFunctionWithName(&kernel_name)
            .ok_or_else(|| "Failed to get Metal kernel function".to_string())?;

        let pipeline = device
            .newComputePipelineStateWithFunction_error(&kernel_fn)
            .map_err(|e| format!("Failed to create compute pipeline state: {:?}", e))?;

        let max_threads = pipeline.maxTotalThreadsPerThreadgroup();
        let threads_per_threadgroup = std::cmp::min(256, max_threads);

        Ok(Self {
            device,
            queue,
            pipeline,
            threads_per_threadgroup,
        })
    }

    /// Batch convert N Jacobian points to Affine points using Montgomery Simultaneous Inversion.
    /// Requires only 1 field inversion for all N points!
    pub fn batch_jacobian_to_affine(jacobians: &[JacobianPoint]) -> Vec<AffinePoint> {
        let n = jacobians.len();
        if n == 0 {
            return Vec::new();
        }

        let mut c = Vec::with_capacity(n);
        let mut running = U256::ONE;

        for j in jacobians {
            if j.infinity || j.z.is_zero() {
                c.push(running);
            } else {
                running = running.field_mul(&j.z);
                c.push(running);
            }
        }

        let mut inv_running = running.field_inv();
        let mut affines = vec![AffinePoint::INFINITY; n];

        for i in (0..n).rev() {
            let j = &jacobians[i];
            if j.infinity || j.z.is_zero() {
                affines[i] = AffinePoint::INFINITY;
            } else {
                let z_inv = if i > 0 {
                    inv_running.field_mul(&c[i - 1])
                } else {
                    inv_running
                };

                let z_inv2 = z_inv.field_square();
                let z_inv3 = z_inv2.field_mul(&z_inv);

                affines[i] = AffinePoint {
                    x: j.x.field_mul(&z_inv2),
                    y: j.y.field_mul(&z_inv3),
                    infinity: false,
                };

                inv_running = inv_running.field_mul(&j.z);
            }
        }

        affines
    }

    /// Fast initial point generation on CPU using incremental stride and Montgomery batch inversion
    pub fn precompute_initial_points(
        start_key: u128,
        thread_count: usize,
        step_count: u32,
    ) -> Vec<MslAffinePoint> {
        let start_u256 = U256::from_u128(start_key);
        let p_start = scalar_mul_g(&start_u256);

        let delta_u256 = U256::from_u64(step_count as u64);
        let delta_affine = scalar_mul_g(&delta_u256);

        let mut jacobians = Vec::with_capacity(thread_count);
        let mut current_j = p_start.to_jacobian();

        for _ in 0..thread_count {
            jacobians.push(current_j);
            current_j = current_j.add_affine(&delta_affine);
        }

        let affines = Self::batch_jacobian_to_affine(&jacobians);
        affines.iter().map(MslAffinePoint::from).collect()
    }

    /// Dispatch a batch search on the Metal GPU.
    pub fn dispatch_block(
        &self,
        start_key: u128,
        thread_count: usize,
        step_count: u32,
        target_hash160: &[u8; 20],
    ) -> Result<Option<u128>, String> {
        let valid_key_count = thread_count
            .checked_mul(step_count as usize)
            .ok_or_else(|| "Metal dispatch key count overflow".to_string())?;
        self.dispatch_exact(
            start_key,
            thread_count,
            step_count,
            valid_key_count,
            target_hash160,
        )
        .map(|outcome| outcome.found_key)
    }

    pub fn dispatch_exact(
        &self,
        start_key: u128,
        thread_count: usize,
        step_count: u32,
        valid_key_count: usize,
        target_hash160: &[u8; 20],
    ) -> Result<DispatchOutcome, String> {
        if thread_count == 0 || step_count == 0 || valid_key_count == 0 {
            return Err("Metal dispatch dimensions must be greater than zero".to_string());
        }
        let capacity = thread_count
            .checked_mul(step_count as usize)
            .ok_or_else(|| "Metal dispatch key count overflow".to_string())?;
        if valid_key_count > capacity || valid_key_count > u32::MAX as usize {
            return Err("Valid key count exceeds Metal dispatch capacity".to_string());
        }

        // Fast Montgomery batch precomputation
        let initial_points = Self::precompute_initial_points(start_key, thread_count, step_count);

        let mut h160_words = [0u32; 5];
        for (i, word) in h160_words.iter_mut().enumerate() {
            let offset = i * 4;
            *word = u32::from_le_bytes(target_hash160[offset..offset + 4].try_into().unwrap());
        }

        let params = SearchParams {
            target_hash160: h160_words,
            step_count,
            valid_key_count: valid_key_count as u32,
        };

        // SAFETY: Metal copies exactly this non-empty POD slice during the call. The pointer and
        // byte length refer to the same live allocation.
        let points_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                NonNull::new(initial_points.as_ptr() as *mut _).expect("non-empty initial points"),
                thread_count * mem::size_of::<MslAffinePoint>(),
                MTLResourceOptions::StorageModeShared,
            )
        }
        .ok_or_else(|| "Failed to allocate Metal points buffer".to_string())?;

        // SAFETY: `params` is a live, initialized POD value and the supplied length is its exact
        // size. Metal copies the bytes before this call returns.
        let params_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                NonNull::from(&params).cast(),
                mem::size_of::<SearchParams>(),
                MTLResourceOptions::StorageModeShared,
            )
        }
        .ok_or_else(|| "Failed to allocate Metal parameter buffer".to_string())?;

        let initial_result = FoundResult::default();
        // SAFETY: `initial_result` is a live, initialized POD value and the supplied length is its
        // exact size. Metal copies the bytes before this call returns.
        let result_buffer = unsafe {
            self.device.newBufferWithBytes_length_options(
                NonNull::from(&initial_result).cast(),
                mem::size_of::<FoundResult>(),
                MTLResourceOptions::StorageModeShared,
            )
        }
        .ok_or_else(|| "Failed to allocate Metal result buffer".to_string())?;

        let command_buffer = self
            .queue
            .commandBuffer()
            .ok_or_else(|| "Failed to create Metal command buffer".to_string())?;
        let encoder = command_buffer
            .computeCommandEncoder()
            .ok_or_else(|| "Failed to create Metal compute encoder".to_string())?;

        encoder.setComputePipelineState(&self.pipeline);
        // SAFETY: All buffers have the exact shader layouts, offset zero is in bounds, and the
        // retained buffer objects stay alive until after `waitUntilCompleted`.
        unsafe {
            encoder.setBuffer_offset_atIndex(Some(&points_buffer), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(&params_buffer), 0, 1);
            encoder.setBuffer_offset_atIndex(Some(&result_buffer), 0, 2);
        }

        let grid_size = MTLSize {
            width: thread_count,
            height: 1,
            depth: 1,
        };
        let tg_size = MTLSize {
            width: self.threads_per_threadgroup,
            height: 1,
            depth: 1,
        };

        encoder.dispatchThreads_threadsPerThreadgroup(grid_size, tg_size);
        encoder.endEncoding();

        let gpu_started = Instant::now();
        command_buffer.commit();
        command_buffer.waitUntilCompleted();
        let gpu_duration = gpu_started.elapsed();

        if command_buffer.status() != MTLCommandBufferStatus::Completed {
            return Err(format!(
                "Metal command buffer did not complete successfully: {:?} ({:?})",
                command_buffer.status(),
                command_buffer.error()
            ));
        }

        // SAFETY: This shared buffer was allocated with exactly `FoundResult` bytes, Metal has
        // completed, and Metal shared-buffer storage is suitably aligned for the POD result type.
        let result_ptr = result_buffer.contents().cast::<FoundResult>().as_ptr();
        let result = unsafe { *result_ptr };

        if result.found_flag != 0 {
            let found_key = start_key
                + (result.found_thread_id as u128) * (step_count as u128)
                + (result.found_step_idx as u128);
            Ok(DispatchOutcome {
                found_key: Some(found_key),
                gpu_duration,
            })
        } else {
            Ok(DispatchOutcome {
                found_key: None,
                gpu_duration,
            })
        }
    }
}
