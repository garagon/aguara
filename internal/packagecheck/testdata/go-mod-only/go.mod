module example.com/mymod

go 1.25

require (
	github.com/stretchr/testify v1.10.0
	example.com/malicious-mod v1.2.3 // indirect
	example.com/other v2.0.0
)

require github.com/spf13/cobra v1.8.0

replace example.com/old => ./local-fork

replace example.com/swapped => example.com/replacement v9.9.9
