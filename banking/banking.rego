package banking.authz

# Enforces modern Rego syntax (requires OPA v0.59.0+)
import rego.v1

# 1. Default Posture
# Always start with a default deny posture for security.
default allow := false

# 2. Main Entry Point
# The overall 'allow' rule evaluates to true if any of the specific conditions are met.
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

# 3. Specific Allow Rules

customer_can_read_own_account if {
	input.action == "read"
	"customer" in input.user.roles
	input.resource.account_owner == input.user.id
}

teller_can_read_any_account if {
	input.action == "read"
	"teller" in input.user.roles
}

customer_can_transfer_funds if {
	input.action == "transfer"
	"customer" in input.user.roles
	input.resource.source_account_owner == input.user.id
	
    # Customers can only transfer up to $10,000 without manager approval
	input.resource.amount <= 10000 
}

manager_can_transfer_large_funds if {
	input.action == "transfer"
	"manager" in input.user.roles
}

# 4. Explicit Denials / Auditing
# Using 'contains' creates a set of violation messages. Useful for returning reasons *why* a request failed.
deny contains msg if {
	input.action == "transfer"
	input.resource.amount > 10000
	not "manager" in input.user.roles
	msg := sprintf("Transfers of $%v exceed the 10,000 limit and require manager approval.", [input.resource.amount])
}

deny contains msg if {
	input.action == "transfer"
	"customer" in input.user.roles
	input.resource.source_account_owner != input.user.id
	msg := "Customers can only transfer funds from their own accounts."
}