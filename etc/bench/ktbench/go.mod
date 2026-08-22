module ktbench

go 1.27

require (
	github.com/mit-pdos/gokv v0.1.1
	github.com/mit-pdos/tulip v0.0.0
	github.com/sanjit-bhat/pav v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/goose-lang/primitive v0.2.1 // indirect
	github.com/goose-lang/std v0.7.0 // indirect
	github.com/tchajed/marshal v0.6.5 // indirect
)

replace github.com/mit-pdos/tulip => /home/claude/tulip

replace github.com/sanjit-bhat/pav => ../../..
