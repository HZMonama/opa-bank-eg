package banking

# Enforces modern Rego syntax (requires OPA v0.59.0+).
import rego.v1

# ----------------------------------------------------------------------------
# Policy entrypoints
# ----------------------------------------------------------------------------

# Default deny posture: a request is rejected unless an allow rule matches.
default allow := false

# Entrypoint: final allow decision.
allow if {
	customer_can_read_own_account
}

allow if {
	teller_can_read_any_account
}

allow if {
	customer_can_transfer_funds
}

allow if {
	manager_can_transfer_large_funds
}

# Entrypoint: set of denial/audit reasons.
deny contains msg if {
	input.action == "transfer"
	input.resource.amount > 10000
	not has_role("manager")
	msg := sprintf("Transfers of $%v exceed the 10,000 limit and require manager approval.", [input.resource.amount])
}

# ----------------------------------------------------------------------------
# Helper rules (non-customer)
# ----------------------------------------------------------------------------

# Helper: tellers can read any account.
teller_can_read_any_account if {
	is_action("read")
	has_role("teller")
}

# Helper: managers can transfer large funds.
manager_can_transfer_large_funds if {
	is_action("transfer")
	has_role("manager")
}

# Helper function: checks the requested action.
is_action(action) if {
	input.action == action
}

# Helper function: checks whether the current user has a role.
has_role(role) if {
	role in input.user.roles
}
