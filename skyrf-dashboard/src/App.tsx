import { useEffect, useState } from 'react';
import { engine, type Device, type Snapshot } from '@/lib/rf/engine';
import type { Protocol } from '@/lib/rf/core';
import { Header } from '@/components/Header';
import { StatsBar } from '@/components/StatsBar';
import { DeviceTable } from '@/components/DeviceTable';
import { AlertsFeed } from '@/components/AlertsFeed';
import { SpectrumPanel } from '@/components/SpectrumPanel';
import { DeviceDrawer } from '@/components/DeviceDrawer';
import { BridgeDialog } from '@/components/BridgeDialog';
import { SuccessKitty } from '@/components/SuccessKitty';

export default function App() {
  const [snap, setSnap] = useState<Snapshot>(() => engine.getSnapshot());
  const [filter, setFilter] = useState<Protocol | 'all'>('all');
  const [selected, setSelected] = useState<Device | null>(null);
  const [bridgeOpen, setBridgeOpen] = useState(false);

  useEffect(() => {
    const id = setInterval(() => setSnap(engine.getSnapshot()), 250);
    return () => clearInterval(id);
  }, []);

  // mantener el drawer sincronizado con el estado vivo del dispositivo
  const selectedLive = selected
    ? snap.devices.find(d => d.id === selected.id) ?? null
    : null;

  return (
    <div className="min-h-100dvh flex flex-col bg-background">
      <Header
        running={snap.capturing}
        wsStatus={snap.wsStatus}
        filter={filter}
        onFilter={setFilter}
        onToggle={() => (snap.capturing ? engine.pause() : engine.start())}
        onReset={() => { engine.reset(); setSnap(engine.getSnapshot()); }}
        onBridgeInfo={() => setBridgeOpen(true)}
      />

      <main className="flex-1 flex flex-col gap-3 p-3 lg:p-4 max-w-[1600px] w-full mx-auto min-h-0">
        <StatsBar snap={snap} />

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-3 min-h-[420px]">
          <div className="xl:col-span-2 min-h-0">
            <DeviceTable
              devices={snap.devices}
              elapsed={snap.elapsed}
              filter={filter}
              onSelect={setSelected}
            />
          </div>
          <div className="min-h-0">
            <AlertsFeed alerts={snap.alerts} />
          </div>
        </div>

        <SpectrumPanel
          spectrum={snap.spectrum}
          labels={snap.spectrumLabels}
          running={snap.capturing}
        />

        <footer className="flex items-center justify-between px-1 pb-2">
          <span className="text-[10px] tracking-[0.18em] text-muted-foreground uppercase">
            SkyRF · RF intelligence framework
          </span>
          <span className="text-[10px] tracking-[0.18em] text-muted-foreground uppercase">
            by Cinn4mor0ll
          </span>
        </footer>
      </main>

      <DeviceDrawer device={selectedLive} onClose={() => setSelected(null)} />
      <BridgeDialog open={bridgeOpen} wsStatus={snap.wsStatus} onClose={() => setBridgeOpen(false)} />
      <SuccessKitty tick={snap.successTick} keyCapture={snap.keyCaptured} />
    </div>
  );
}
