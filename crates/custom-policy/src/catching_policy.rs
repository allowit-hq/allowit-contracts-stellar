use allowit::prelude::*;
/// My agent may pay only destinations I approve. It may exceed its daily spending cap twice; count
/// each time. A payment that names an invoice must stay within my invoice cap. A refund must name
/// its order number.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only destinations I approve"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    match allowit::daily_spending_limit(ctx, &ctx.params[allowit::DAILY_SPENDING_LIMIT]) {
        // "It may exceed its daily spending cap twice"
        Err(AllowitError::DailySpendingLimitExceeded) => {
            // "count each time"
            let over: u64 = allowit::get_state(ctx, "over_day_cap")?.unwrap_or(0);
            if over >= 2 {
                return Err(AllowitError::DailySpendingLimitExceeded);
            }
            allowit::set_state(ctx, "over_day_cap", over + 1)?;
        }
        other => {
            other?;
        }
    }
    // "A payment that names an invoice"
    if ctx.request.args.contains("invoice") {
        // "must stay within my invoice cap"
        allowit::payment_limit(ctx, &ctx.params["invoice_cap"])?;
    }
    // "A refund"
    if ctx.request.args.contains("refund") {
        // "must name its order number"
        let _order: u64 = allowit::arg(ctx, "order");
    }
    Ok(())
}
