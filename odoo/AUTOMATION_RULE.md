# Automation Rule — "Notify Relayer on PO Confirm"

This rule lives in the Odoo database (Settings → Technical → Automation →
Automated Actions), not as a file, so it isn't tracked by git directly.
Recreate it manually if setting up a fresh Odoo instance:

- **Model:** Purchase Order
- **Trigger:** On Update
- **Trigger Fields:** Status (state) — NOT "Activity State," a similarly
  named but unrelated field
- **Before Update Domain:** [('state', '!=', 'purchase')]
- **Apply on:** [('state', '=', 'purchase')]
- **Action Type:** Execute Python Code
- **Code:** `record.action_notify_relayer()`

Requires the `base_automation` module (Automation Rules) to be installed,
and the `zhets_approval_anchor` module (this folder) installed, which adds
`action_notify_relayer()` to `purchase.order`.
