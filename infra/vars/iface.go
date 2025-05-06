package vars

type SlidingWindowLimiterIFace interface {
	IsLimited(string) bool
	RecordError(string)
}
