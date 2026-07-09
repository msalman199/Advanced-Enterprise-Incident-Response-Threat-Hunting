#!/usr/bin/env python3
import json

# Load the detection coverage layer
with open('detection-coverage-layer.json', 'r') as f:
    coverage_data = json.load(f)

print("Detection Gap Analysis Report")
print("=" * 40)

for technique in coverage_data['techniques']:
    technique_id = technique['techniqueID']
    comment = technique['comment']
    
    if 'Limited' in comment or 'Low' in comment:
        print(f"GAP IDENTIFIED: {technique_id}")
        print(f"Issue: {comment}")
        print(f"Recommendation: Implement enhanced detection controls")
        print("-" * 30)

print("\nAnalysis complete. Review gaps and prioritize improvements.")
