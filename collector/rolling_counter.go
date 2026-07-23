package collector

// rollingCounter keeps an observed rolling-window value monotonic. Decreases
// expire old data rather than represent new traffic, so only positive deltas
// are added to the synthesized value.
type rollingCounter struct {
	lastRaw     float64
	cumulative  float64
	initialized bool
}

func (c *rollingCounter) update(raw float64) float64 {
	if !c.initialized {
		c.lastRaw = raw
		c.cumulative = raw
		c.initialized = true

		return c.cumulative
	}

	if raw > c.lastRaw {
		c.cumulative += raw - c.lastRaw
	}

	c.lastRaw = raw

	return c.cumulative
}
