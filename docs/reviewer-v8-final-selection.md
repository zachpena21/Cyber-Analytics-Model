# Reviewer v8 final selection

Select the unchanged frozen structural primary as the submission model weights.
Keep its fixed provenance fold-zero trees, adapter route 0.15 and software
threshold 0.6882517225516912. Do not refit or select another seed on deadline day.

| Candidate | Recorded evidence | Disposition |
|---|---|---|
| Frozen structural primary | 2/526 benign errors; 75/92 malware detected | Final selected weights |
| Frozen bounded comparison | Same decisions on that batch | Retain; no demonstrated benefit |
| Frozen expanded v8 | 163/526 benign errors; 85/92 malware detected | Retain as research reference |
| Original-data imports ensemble | Development panel: 356/481 malware, 23/12,764 benign errors | Retain; lacks comparable untouched validation |
| Earlier targeted-coverage imports ensemble | Development panel: 307/481 malware, 24/12,764 benign errors | Retain; loses the 76-row watch group |
| Native-coverage imports ensemble | Development panel: 290/481 malware, 14/12,764 benign errors; 3/15 native errors | Retain; 20 malware regressions versus 3 rescues |
| Group-balanced weighting | Reduced malware detection and group recall | Retain; no promotion |
| Reviewer v7 | 169/526 benign errors; 67/92 malware detected on the structural comparison batch | Retain as runtime reference |

The panels are different populations and cannot be treated as one ranking table.
The final choice preserves the preselected structural model with the strongest
recorded low-FPR evaluation evidence. Later refinement experiments are not
independent validation, and no candidate is claimed to meet the 95% TPR goal on
hidden data. Preserve all weights, source scripts, reports and split manifests.

Use [the finalization workflow](../scripts/finalize_reviewer_v8.md) to export the
selected trees into the existing runtime format and check cached-vector parity.
This selects weights; it does not establish Docker submission readiness. The
Python base-image migration and end-to-end runtime checks remain required.
