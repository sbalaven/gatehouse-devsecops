# Demonstrate a failing gate

Use a disposable branch and pull request after the baseline workflow passes. This exercise needs no real secret, vulnerable dependency, public target, or active exploit.

1. Create a branch named `demo/security-gate`.
2. Add `app/gate_probe.py` containing the following unused function:

   ```python
   def unsafe_probe(expression):
       return eval(expression)
   ```

3. Do not import or call it. Commit and open a pull request.
4. Confirm that Semgrep reports `no-eval` and the `release-gate` job fails. Download `semgrep.json` and capture the actual Actions result.
5. Delete the probe file, commit again, and verify the updated workflow succeeds if no other gates report problems.
6. Retain links to both runs in your project notes. Close the demo PR if no useful changes remain.

This validates one source-analysis gate and the aggregate gate. It does not prove that every scanner detects every vulnerability. An unavailable scanner or feed should also fail the workflow; distinguish a tool error from a real finding when reviewing reports.
