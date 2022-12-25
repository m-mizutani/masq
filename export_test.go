package masq

func NewMasq(options ...Option) *masq {
	return newMasq(options...)
}

func (x *masq) Conceal(v any) any {
	return x.conceal(v)
}
