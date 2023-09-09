package masq_test

import (
	"github.com/m-mizutani/masq"
)

func ExampleMaskString() {
	out := &fixedTimeWriter{}

	type myRecord struct {
		ID    string
		Phone string
	}
	record := myRecord{
		ID:    "m-mizutani",
		Phone: "090-0000-0000",
	}

	logger := newLogger(out, masq.New(
		// custom redactor
		masq.WithFieldName("Phone", masq.MaskString('*')),
	))
	logger.With("record", record).Info("Got record")
	out.Flush()
	// Output:
	// {"level":"INFO","msg":"Got record","record":{"ID":"m-mizutani","Phone":"*************"},"time":"2022-12-25T09:00:00.123456789"}
}
