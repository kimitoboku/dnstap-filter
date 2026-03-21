package filter

// AddrMode controls which address fields a filter matches against.
type AddrMode int

const (
	AddrBoth AddrMode = iota // match QueryAddress OR ResponseAddress
	AddrSrc                  // match QueryAddress only
	AddrDst                  // match ResponseAddress only
)
