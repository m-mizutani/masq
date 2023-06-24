package masq

func NewMasq(options ...Option) *masq {
	return newMasq(options...)
}

func (x *masq) Redact(v any) any {
	return x.redact("", v)
}
