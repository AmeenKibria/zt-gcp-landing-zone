package landingzone.testlib

# Builders for the parts of `terraform show -json` that the rules read.
# Every unit test builds its input from these, so the shape the tests assume is
# written down in one place and can be compared with a real plan.

change(type, actions, mode, after, unknown) := {
	"address": concat(".", [type, "t"]),
	"mode": mode,
	"type": type,
	"name": "t",
	"change": {"actions": actions, "after": after, "after_unknown": unknown},
}

# A resource the plan creates, with every attribute known.
create(type, after) := change(type, ["create"], "managed", after, {})

# A resource the plan creates, with some attributes unknown until apply.
create_unknown(type, after, unknown) := change(type, ["create"], "managed", after, unknown)

# A resource the plan deletes. `after` is null in a real plan.
delete(type) := change(type, ["delete"], "managed", null, {})

# A data source read during planning. It describes something that exists; it
# proposes nothing.
read(type, after) := change(type, ["read"], "data", after, {})

plan(changes) := {"format_version": "1.2", "resource_changes": changes}

# The CIS identifiers a denial cites, read from its label: "[CIS 3.6/3.7] ..."
# cites 3.6 and 3.7. Tests check the identifier, not the spelling of the label.
cited(d) := {id | startswith(d, "[CIS "); label := substring(d, 5, indexof(d, "]") - 5); some id in split(label, "/")}

cites(denials, id) if {
	some d in denials
	id in cited(d)
}

cites_none(denials, id) if {
	count({d | some d in denials; id in cited(d)}) == 0
}

has_label(denials, label) if {
	some d in denials
	startswith(d, label)
}

no_label(denials, label) if {
	count({d | some d in denials; startswith(d, label)}) == 0
}

sa := "serviceAccount:app@zt-lz-sandbox.iam.gserviceaccount.com"

user := "user:developer@example.com"

group := "group:platform-emergency@example.com"
