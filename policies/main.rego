# Aggregator.
#
# Each domain package under landingzone.* defines its own deny set. Querying
# them with data.landingzone[_].deny works, but the JSON that comes back
# changes shape depending on how many packages happened to produce a result.
# That makes the pipeline brittle and hard to read.
#
# This collects every denial into one stable set, so the pipeline evaluates a
# single query and gets a single list of strings.

package main

deny contains msg if {
	some pkg
	msg := data.landingzone[pkg].deny[_]
}
