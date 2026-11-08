use allowit::prelude::*;
/// Let my agent pay our suppliers from this wallet. Limit every payment, limit its total spending,
/// limit its spending each day and limit the daily volume it moves. Limit how many payments it makes.
/// Pay only suppliers I approve, use only USDC, and stop when the params expire. Let it only make
/// payments.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Limit every payment"
    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;
    // "limit its total spending"
    allowit::lifetime_spending_limit(ctx, &ctx.params[allowit::LIFETIME_SPENDING_LIMIT])?;
    // "limit its spending each day"
    allowit::daily_spending_limit(ctx, &ctx.params[allowit::DAILY_SPENDING_LIMIT])?;
    // "limit the daily volume it moves"
    allowit::daily_volume_limit(ctx, &ctx.params[allowit::DAILY_VOLUME_LIMIT])?;
    // "Limit how many payments it makes"
    allowit::call_limit(ctx, &ctx.params[allowit::CALL_LIMIT])?;
    // "Pay only suppliers I approve"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    // "use only USDC"
    allowit::tokens(ctx, &ctx.params[allowit::TOKENS])?;
    // "stop when the params expire"
    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;
    // "only make payments"
    allowit::operations(ctx, &ctx.params[allowit::OPERATIONS])?;
    Ok(())
}
