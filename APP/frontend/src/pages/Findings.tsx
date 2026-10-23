import { FindingsTable } from "../components/FindingsTable";
import { PageHead } from "../components/PageHead";

export function FindingsPage() {
  return (
    <>
      <PageHead eyebrow="Findings & remediation" title="Every finding," highlight="one workflow"
        sub="Detect → Explain → Propose → Validate → Approve → Apply → Verify. Open a finding to see evidence, the patch, guardrail checks and approval history." />
      <FindingsTable title="All findings" />
    </>
  );
}
