export default function Integrations() {
  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-2xl font-semibold text-neutral-100 tracking-tight">Integrations</h1>
      <p className="text-sm text-neutral-500 mt-1">Connect Aegis to your CI/CD pipelines and issue trackers.</p>
      
      <div className="mt-10 bg-[#111113] border border-neutral-800 rounded-xl p-8 flex items-center justify-center">
        <p className="text-neutral-500 text-sm">No active integrations found.</p>
      </div>
    </div>
  );
}
