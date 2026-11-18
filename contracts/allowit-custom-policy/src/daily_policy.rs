use allowit::prelude::*;
/// My agent may pay only destinations I approve, and at most two payments each day; count them.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only destinations I approve"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    // "at most two payments each day; count them"
    let payments: u64 = allowit::get_state(ctx, "day_payments")?.unwrap_or(0);
    if payments >= 2 {
        return Err(AllowitError::CallLimitExceeded);
    }
    allowit::set_state(ctx, "day_payments", payments + 1)?;
    Ok(())
}
