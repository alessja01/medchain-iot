import { use, useMemo, useState } from "react";
import{Card, CardContent, CardHeader, CardTitle, CardDescription} from "@/components/ui/card";
import {Badge} from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

//da sostituire 
const MOCK_REPORTS = [
    { id:1, deviceId: "esp32-001", timestamp:1736891000, integrity: "OK", offchainRef: 1, hash: "a1b2..." },
    { id: 2, deviceId: "esp32-001", timestamp: 1736891300, integrity: "OK", offchainRef: 2, hash: "c3d4..." },
    { id: 3, deviceId: "esp32-002", timestamp: 1736891600, integrity: "FAIL", offchainRef: 7, hash: "deadbeef..." },
];

//componente riceve un value e restituisce un badge con colore diverso in base al valore
function IntegrityBadge({value}){
    if (value === "OK") return <Badge className="bg-green-600 hover:bg-green-600">OK</Badge>;
    if(value === "FAIL") return <Badge variant="destructive">FAIL</Badge>;
    return <Badge variant="secondary">-</Badge>;
}

//trasforma timestamp epoch in data leggibile
function formatEpoch(ts){
    if(!ts) return "-";
    const d = new Date(ts * 1000);
    return d.toLocaleString();
}

export default function Dashboard(){
    //crea uno stato react dove reports è la lista di report e setReports serve per aggiornare la lista
    const [reports, setReports] = useState(MOCK_REPORTS);
    //contiente l'id del report selezionato ( preondi l'id del primo report o null se la lista è vuota)
    const [selectedID, setSelectedID] = useState(reports[0]?.id ?? null);
    //query è il testo che scrivi nella barra di ricerca
    const [query, setQuery] = useState("");


    //restituisce il report selezionato in base all'id
    const selected= useMemo(
        () => reports.find((r) => r.id === selectedID) ?? null,
        [reports, selectedID]
    );

    //lista dei report filtrata in base alla query di ricerca
    const filtered= useMemo(() =>{
        //trasforma la query in minuscolo e rimuove gli spazi iniziali e finali
        const q= query.trim().toLowerCase();
        if(!q) return reports;
        return reports.filter((r) =>{
            return (
                String(r.id).includes(q) ||
                r.deviceId.toLowerCase().includes(q) ||
                String(r.offchainRef).includes(q) ||
                (r.hash ?? "").toLowerCase().includes(q)
            );
        });
    }, [reports, query]);

    function refreshMock(){
        //per ora simula refresh. Poi qui faremo fetch API
        setReports((prev)=>[...prev]);
    }

    return (
     <div className="min-h-screen bg-background">
      <div className="mx-auto max-w-6xl p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="scroll-m-20 text-4xl font-extrabold tracking-tight">
              MedChain Dashboard
            </h1>
            <p className="text-muted-foreground mt-2">
              Report cifrati off-chain + hash on-chain + accesso controllato
            </p>
          </div>

          <Button onClick={refreshMock}>Aggiorna</Button>
        </div>

        <Separator />

        {/* KPI Cards */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Report totali</CardDescription>
               <CardTitle className="text-3xl">{reports.length}</CardTitle>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Device unici</CardDescription>
              <CardTitle className="text-3xl">
                {new Set(reports.map((r) => r.deviceId)).size}
              </CardTitle>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Integrity OK</CardDescription>
              <CardTitle className="text-3xl">
                {reports.filter((r) => r.integrity === "OK").length}
              </CardTitle>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription>Integrity FAIL</CardDescription>
                            <CardTitle className="text-3xl">
                {reports.filter((r) => r.integrity === "FAIL").length}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>

        {/* Main grid */}
        <div className="grid gap-6 lg:grid-cols-[1.3fr_0.7fr]">
          {/* Table card */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <CardTitle>Reports</CardTitle>
                  <CardDescription>Seleziona un report per vedere i dettagli</CardDescription>
                </div>
                <Input
                  className="max-w-xs"
                  placeholder="Cerca id, device, hash..."
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </div>
            </CardHeader>

            <CardContent>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[80px]">ID</TableHead>
                      <TableHead>Device</TableHead>
                                            <TableHead>Timestamp</TableHead>
                      <TableHead>Integrity</TableHead>
                      <TableHead className="text-right">OffchainRef</TableHead>
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {filtered.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-center text-muted-foreground">
                          Nessun report trovato.
                        </TableCell>
                      </TableRow>
                    ) : (
                      filtered.map((r) => (
                        <TableRow
                          key={r.id}
                          className={r.id === selectedId ? "bg-muted/50" : ""}
                          onClick={() => setSelectedId(r.id)}
                          style={{ cursor: "pointer" }}
                        >
                          <TableCell className="font-medium">{r.id}</TableCell>
                          <TableCell>{r.deviceId}</TableCell>
                          <TableCell className="text-muted-foreground">{formatEpoch(r.timestamp)}</TableCell>
                          <TableCell><IntegrityBadge value={r.integrity} /></TableCell>
                          <TableCell className="text-right">{r.offchainRef}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                               </Table>
              </div>
            </CardContent>
          </Card>

          {/* Details card */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle>Dettagli</CardTitle>
              <CardDescription>
                Metadati del report selezionato (nessun dato sensibile on-chain)
              </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              {!selected ? (
                <div className="text-muted-foreground">Seleziona un report dalla tabella.</div>
              ) : (
                <>
                  <div className="space-y-1">
                    <div className="text-sm text-muted-foreground">Report ID</div>
                    <div className="text-lg font-semibold">{selected.id}</div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-sm text-muted-foreground">Device</div>
                                        <div className="font-medium">{selected.deviceId}</div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-sm text-muted-foreground">Timestamp</div>
                    <div className="font-medium">{formatEpoch(selected.timestamp)}</div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-sm text-muted-foreground">Integrity</div>
                    <IntegrityBadge value={selected.integrity} />
                  </div>

                  <div className="space-y-1">
                    <div className="text-sm text-muted-foreground">OffchainRef (DB / IPFS)</div>
                    <div className="font-medium">{selected.offchainRef}</div>
                  </div>

                  <div className="space-y-2">
                    <div className="text-sm text-muted-foreground">Hash (ancoraggio on-chain)</div>
                    <code className="block rounded-md bg-muted p-2 text-xs break-all">
                      {selected.hash}
                    </code>
                  </div>

                  <div className="flex flex-col gap-2 pt-2">
                    <Button variant="default">Verifica integrità</Button>
                    <Button variant="secondary">Decifra (se autorizzato)</Button>
                  </div>

                  <p className="text-xs text-muted-foreground pt-2">
                    Nota: i bottoni adesso sono “UI only”. Nel prossimo step li colleghiamo all’API.
                  </p>
                </>
              )}
                 </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}