export default function Scans() {
  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-2xl font-semibold text-neutral-100 tracking-tight">Scans</h1>
      <p className="text-sm text-neutral-500 mt-1">View historical scan results and reports.</p>
      
      <div className="mt-10 bg-[#111113] border border-neutral-800 rounded-xl p-8 flex items-center justify-center">
        <p className="text-neutral-500 text-sm">No historical scans available.</p>
      </div>
    </div>
  );
}
