package banking

# Enforces modern Rego syntax (requires OPA v0.59.0+).
import rego.v1

# ----------------------------------------------------------------------------
# Helper rules (customer-specific)
# ----------------------------------------------------------------------------

# Helper: customers can read only their own account.
customer_can_read_own_account if {
	is_action("read")
	has_role("customer")
	input.resource.account_owner == input.user.id
}

# Helper: customers can transfer from their own account up to a limit.
customer_can_transfer_funds if {
	is_action("transfer")
	has_role("customer")
	input.resource.source_account_owner == input.user.id
	customer_transfer_within_limit
}

# Helper: customer transfer amount must be at or below the configured limit.
customer_transfer_within_limit if {
	input.resource.amount <= customer_transfer_limit
}

# Helper constant: maximum transfer amount customers can self-approve.
customer_transfer_limit := 10000

# ----------------------------------------------------------------------------
# Policy entrypoint extensions
# ----------------------------------------------------------------------------

# Entrypoint extension: customer transfer ownership mismatch produces an audit reason.
deny contains msg if {
	is_action("transfer")
	has_role("customer")
	input.resource.source_account_owner != input.user.id
	msg := "Customers can only transfer funds from their own accounts."
}
