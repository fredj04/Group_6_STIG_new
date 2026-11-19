# Group_6_STIG
Network Security project (CSE 484)

**STIG Compliance Mapper** traces every rule in a DISA STIG benchmark to its
Control Correlation Identifiers (CCIs) and on to NIST SP 800-53 controls.

## Running the GUI
Requires Python 3.8+ (standard library only, no installs).

```
python stig_mapper_gui.py
```
or double-click `Run STIG Mapper.bat` on Windows.

The app starts empty. Use **Browse…** to choose a CCI list and a STIG benchmark
(the repo includes `CCI_List.xml` and `U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml`),
then click **Load & Map**.

## Features
- Summary of rules by severity (CAT I / II / III), unique CCIs, NIST controls, and gaps
- Searchable, sortable traceability matrix with severity / family / needs-review filters
- Rule detail pane: CCI definition, NIST control, vulnerability discussion, check and fix text
- Control-family breakdown with a stacked severity chart
- Choose NIST SP 800-53 Revision 5 or Revision 4 as the baseline
- Export the current view to CSV, or a formatted HTML report (printable to PDF)

## Files
| File | Purpose |
|---|---|
| `stig_mapper_gui.py` | Desktop GUI application |
| `main.py` | Original command-line version |
| `CCI_List.xml` | DISA CCI list |
| `U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml` | Windows 11 STIG V2R11 |
