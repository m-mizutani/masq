package masq_test

import (
	"github.com/m-mizutani/masq"
)

func ExampleMaskWithSymbol() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
		Email string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
		// too long email address
		Email: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@example.com",
	}

	logger := newLogger(out, masq.New(
		masq.WithFieldName("Phone", masq.MaskWithSymbol('*', 32)),
		masq.WithFieldName("Email", masq.MaskWithSymbol('*', 12)),
	))
	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"Email":"************ (remained 36 chars)","ID":"m-mizutani","Phone":"*************"},"time":"2022-12-25T09:00:00.123456789"}
}
