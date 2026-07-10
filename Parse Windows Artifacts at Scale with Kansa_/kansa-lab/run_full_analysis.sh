#!/bin/bash

echo "=========================================="
echo "    Kansa Windows Artifact Analysis"
echo "=========================================="
echo

# Create results directory
mkdir -p ~/kansa-lab/results

echo "1. Analyzing Event Logs..."
python3 ~/kansa-lab/analyze_eventlogs.py > ~/kansa-lab/results/eventlog_analysis.txt
echo "   Results saved to: ~/kansa-lab/results/eventlog_analysis.txt"
echo

echo "2. Analyzing Registry Artifacts..."
python3 ~/kansa-lab/analyze_registry.py > ~/kansa-lab/results/registry_analysis.txt
echo "   Results saved to: ~/kansa-lab/results/registry_analysis.txt"
echo

echo "3. Analyzing Process Data..."
python3 ~/kansa-lab/analyze_processes.py > ~/kansa-lab/results/process_analysis.txt
echo "   Results saved to: ~/kansa-lab/results/process_analysis.txt"
echo

echo "4. Correlating IOCs..."
python3 ~/kansa-lab/correlate_iocs.py > ~/kansa-lab/results/ioc_correlation.txt
echo "   Results saved to: ~/kansa-lab/results/ioc_correlation.txt"
echo

echo "=========================================="
echo "Analysis Complete!"
echo "=========================================="
echo "Results directory: ~/kansa-lab/results/"
ls -la ~/kansa-lab/results/
