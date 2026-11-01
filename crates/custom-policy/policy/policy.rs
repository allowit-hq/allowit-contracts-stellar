use allowit::prelude::*;
/// Let my agent pay our suppliers from this wallet. Cap every payment, cap its total spending,
/// cap its spending each day and cap the daily volume it moves. Limit how many payments it makes.
/// Pay only suppliers I approve, use only USDC, and stop when the params expire. Let it only make
/// payments.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Cap every payment"
    allowit::payment_limit(ctx, ctx.params.get(allowit::PAYMENT_LIMIT))?;
    // "cap its total spending"
    allowit::lifetime_spending_limit(ctx, ctx.params.get(allowit::LIFETIME_SPENDING_LIMIT))?;
    // "cap its spending each day"
    allowit::daily_spending_limit(ctx, ctx.params.get(allowit::DAILY_SPENDING_LIMIT))?;
    // "cap the daily volume it moves"
    allowit::daily_volume_limit(ctx, ctx.params.get(allowit::DAILY_VOLUME_LIMIT))?;
    // "Limit how many payments it makes"
    allowit::call_limit(ctx, ctx.params.get(allowit::CALL_LIMIT))?;
    // "Pay only suppliers I approve"
    allowit::destinations(ctx, ctx.params.get(allowit::DESTINATIONS))?;
    // "use only USDC"
    allowit::tokens(ctx, ctx.params.get(allowit::TOKENS))?;
    // "stop when the params expire"
    allowit::expires_at(ctx, ctx.params.get(allowit::EXPIRES_AT))?;
    // "only make payments"
    allowit::operations(ctx, ctx.params.get(allowit::OPERATIONS))?;
    Ok(())
}
