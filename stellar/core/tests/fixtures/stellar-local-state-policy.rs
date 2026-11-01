use allowit::v1::prelude::*;
async fn _execute(request: &Context, grant: &Grant, state: &State) -> Result<Spent, PolicyError> {
    let daily = self::daily_cap(request, state)?;
    let after_daily = allowit::with_spent(state, daily)?;
    let total = self::total_cap(request, &after_daily)?;
    let after_total = allowit::with_spent(&after_daily, total)?;
    let calls = self::call_cap(request, &after_total)?;
    let n = allowit::state_get(&calls, "custom_count", 0u64)?;
    let final_spent = allowit::state_set(calls, "custom_count", n + 1)?;
    Ok(final_spent)
}
