use allowit::prelude::*;
/// My agent may pay or deposit only to destinations I approve. A deposit into a vault must also
/// keep total spending within its cap.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only to destinations I approve"
    allowit::destinations(ctx, ctx.params.get(allowit::DESTINATIONS))?;
    // "A deposit into a vault"
    if ctx.request.operation == AllowitOperation::deposit {
        // "must also keep total spending within its cap"
        allowit::lifetime_spending_limit(ctx, ctx.params.get(allowit::LIFETIME_SPENDING_LIMIT))?;
    }
    Ok(())
}
