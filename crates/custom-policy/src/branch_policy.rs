use allowit::prelude::*;
/// My agent may pay or deposit only to destinations I approve. A deposit into a vault must also
/// keep total spending within its cap.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "only to destinations I approve"
    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
    // "A deposit into a vault"
    if ctx.request.operation == AllowitOperation::deposit {
        // "must also keep total spending within its cap"
        allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
    }
    Ok(())
}
