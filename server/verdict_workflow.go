package server

// fireVerdictWorkflow 驱动目标验收队列的推进。
func (sc *Scheduler) fireVerdictWorkflow() {
	if sc == nil || sc.pg == nil {
		return
	}
	sc.runVerificationQueue()
}
