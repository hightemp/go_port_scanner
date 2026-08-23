package report

// FilterWorking returns a copy of document containing only successful
// discovery results, open TCP ports, and successful protocol probes. Scan
// status and a top-level interruption error are preserved so partial reports
// remain identifiable.
func FilterWorking(document Document) Document {
	filtered := document
	workingTargets := make(map[string]struct{})

	filtered.Discovery = make([]DiscoveryResult, 0, len(document.Discovery))
	for _, result := range document.Discovery {
		if !result.Available {
			continue
		}
		result.Error = ""
		filtered.Discovery = append(filtered.Discovery, result)
		workingTargets[result.Target] = struct{}{}
	}

	filtered.OpenPorts = make([]OpenPort, 0, len(document.OpenPorts))
	for _, openPort := range document.OpenPorts {
		workingTargets[openPort.Target] = struct{}{}
		filteredProbes := make([]ProbeResult, 0, len(openPort.Probes))
		for _, probe := range openPort.Probes {
			if probe.Status != "ok" {
				continue
			}
			probe.Error = ""
			filteredProbes = append(filteredProbes, probe)
		}
		openPort.Probes = filteredProbes
		filtered.OpenPorts = append(filtered.OpenPorts, openPort)
	}

	filtered.RequestedTargets = filterWorkingTargets(document.RequestedTargets, workingTargets)
	filtered.ScannedTargets = filterWorkingTargets(document.ScannedTargets, workingTargets)
	workingChecks := len(filtered.OpenPorts)
	filtered.Summary = Summary{
		Total:     workingChecks,
		Completed: workingChecks,
		Open:      workingChecks,
	}
	return filtered
}

func filterWorkingTargets(targets []string, working map[string]struct{}) []string {
	filtered := make([]string, 0, len(targets))
	for _, target := range targets {
		if _, exists := working[target]; exists {
			filtered = append(filtered, target)
		}
	}
	return filtered
}
