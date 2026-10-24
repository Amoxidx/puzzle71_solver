// Test-only entry points appended to the actual production shader. All arithmetic,
// point collection, inverse-Z conversion and HASH160 helpers come from that shader.
kernel void test_batch16_hashes(
    device const AffinePoint* initial_points [[buffer(0)]],
    constant SearchParams& params [[buffer(1)]],
    device uint32_t* outputs [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    uint64_t thread_base = (uint64_t)tid * (uint64_t)params.step_count;
    if (thread_base >= (uint64_t)params.valid_key_count) return;
    uint thread_keys = (uint)min((uint64_t)params.step_count,
        (uint64_t)params.valid_key_count - thread_base);
    AffinePoint base = initial_points[tid];
    JacobianPoint current = {base.x, base.y, {{1,0,0,0,0,0,0,0}}, base.is_inf};
    AffinePoint generator = {
        {G_X_LIMBS[0], G_X_LIMBS[1], G_X_LIMBS[2], G_X_LIMBS[3], G_X_LIMBS[4], G_X_LIMBS[5], G_X_LIMBS[6], G_X_LIMBS[7]},
        {G_Y_LIMBS[0], G_Y_LIMBS[1], G_Y_LIMBS[2], G_Y_LIMBS[3], G_Y_LIMBS[4], G_Y_LIMBS[5], G_Y_LIMBS[6], G_Y_LIMBS[7]},
        false
    };
    for (uint step = 0; step < thread_keys;) {
        uint count = min((uint)AFFINE_BATCH_SIZE, thread_keys - step);
        JacobianPoint points[AFFINE_BATCH_SIZE];
        U256 inverses[AFFINE_BATCH_SIZE];
        collect_jacobian_points(current, generator, points, count);
        batch_inverse_z(points, inverses, count);
        for (uint i = 0; i < count; ++i) {
            uint row = (uint)(thread_base + step + i) * 6;
            for (uint word = 0; word < 6; ++word) outputs[row + word] = 0;
            if (u256_is_zero(inverses[i])) continue;
            uint32_t hash[5];
            affine_hash160(affine_from_inverse_z(points[i], inverses[i]), hash);
            outputs[row] = 1;
            for (uint word = 0; word < 5; ++word) outputs[row + 1 + word] = hash[word];
        }
        step += count;
    }
}

kernel void test_batch16_explicit_points(
    device const JacobianPoint* inputs [[buffer(0)]],
    constant uint& count [[buffer(1)]],
    device uint32_t* outputs [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid != 0 || count > AFFINE_BATCH_SIZE) return;
    JacobianPoint points[AFFINE_BATCH_SIZE];
    U256 inverses[AFFINE_BATCH_SIZE];
    for (uint i = 0; i < count; ++i) points[i] = inputs[i];
    batch_inverse_z(points, inverses, count);
    for (uint i = 0; i < count; ++i) {
        uint row = i * 6;
        for (uint word = 0; word < 6; ++word) outputs[row + word] = 0;
        if (u256_is_zero(inverses[i])) continue;
        uint32_t hash[5];
        affine_hash160(affine_from_inverse_z(points[i], inverses[i]), hash);
        outputs[row] = 1;
        for (uint word = 0; word < 5; ++word) outputs[row + 1 + word] = hash[word];
    }
}
