import time
from collections import defaultdict

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
from pox.lib.recoco import Timer

log = core.getLogger()

POLL_INTERVAL   = 2       # statistiche flusso 
REPORT_INTERVAL = 20      # distribuzione del carico tra gli spine
IDLE_TIMEOUT    = 10      # terminazione della regola se non ci sono pacchetti per 10s
HARD_TIMEOUT    = 120     # ultimo byte di un flusso -> termina la regola dopo 120s
MIN_ROUND_GAP   = 5       # conns con lo stesso sport entro 5s -> stesso round
DV_MIN          = 500000  # ignora le piccole connessioni di controllo/ACK per Dv
#_report_distribution monitora la divisione dello spine
# e promuove automaticamente self.routing_mode da "single" -> "balanced"
ROUTING_MODE    = "single"  #forza ogni flusso su un solo spine (baseline per confronto).
UNEVEN_RATIO    = 1.25   # max/min spine-load ratio above which we call it "uneven"


class MLRoutingApp(object):
    #teoria degli eventi di POX
    def __init__(self):
        core.openflow.addListeners(self)
        core.openflow_discovery.addListeners(self)
        #topologia switch-switch e switch-host
        self.graph = {}               # dpid -> {neighbor_dpid: out_port}
        self.mac_to_location = {}      # mac  -> (dpid, port)
        
        self.collectors = {
            IPAddr("10.0.1.1"): "blue",
            IPAddr("10.0.1.2"): "green",
            IPAddr("10.0.1.3"): "red",
            IPAddr("10.0.1.4"): "yellow",
        }

        # discovery / control state 
        self.active_workers   = {v: set() for v in self.collectors.values()}
        self.training_start_t = {v: None  for v in self.collectors.values()}
        self.spine_load       = {v: defaultdict(int) for v in self.collectors.values()}
        self.global_start     = None    # tempo in cui il primo worker è stato visto (per calcolare phi_v)

        # reactive routing state 
        self.routing_mode = ROUTING_MODE   # può cambiare runtime se si rileva congestione

        # traffic-characterization state 
        self.worker_training  = {}               # worker_ip -> nome del training
        self.conn_seen        = set()            # insieme delle coppie (worker_ip, tcp_src_port) processate almeno una volta
        self.round_start      = {}               # worker_ip -> timestamp dell'ultimo round iniziato per quel worker
        self.first_round_start = {}              # worker_ip -> timestamp del primo round, mai più modificato
        self.round_count      = defaultdict(int) # worker_ip → quanti round ha completato finora quel worker
        self.Tv_samples       = defaultdict(list) # worker_ip -> [inter-round gaps] lista scarti temporali tra round successivi (per calcolare Tv)
        self.phi              = {}               # worker_ip -> phase offset
        self.conn_dpids       = defaultdict(set)  # (wip, sport) -> insieme di dpid degli switch che hanno confermato che quel flusso è ancora vivo
        self.conn_bytes       = {}                 # (wip, sport) -> byte_count più alto osseravto

        Timer(POLL_INTERVAL,   self._request_stats,       recurring=True)
        Timer(REPORT_INTERVAL, self._report_distribution, recurring=True)
        log.info("ML Routing up  |  starting mode=%s", self.routing_mode)

     # Contabilità della topologia
    
    # quando uno switch stabilisce il canale di controllo col controller
    def _handle_ConnectionUp(self, event):
        self.graph.setdefault(event.dpid, {})
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.command = of.OFPFC_DELETE
        event.connection.send(msg)
        log.info("Switch connected: %s", dpid_to_str(event.dpid))
    #ogni link scoperto aggiorna il grafo in entrambe le direzioni
    def _handle_LinkEvent(self, event):
        lk = event.link
        if event.added:
            self.graph.setdefault(lk.dpid1, {})[lk.dpid2] = lk.port1
            self.graph.setdefault(lk.dpid2, {})[lk.dpid1] = lk.port2
            log.info("Link: %s <-> %s", dpid_to_str(lk.dpid1), dpid_to_str(lk.dpid2))
        elif event.removed:
            self.graph.get(lk.dpid1, {}).pop(lk.dpid2, None)
            self.graph.get(lk.dpid2, {}).pop(lk.dpid1, None)

    def _is_spine(self, dpid):
        # spines reach every leaf (degree > 2); leaves reach only the 2 spines.
        return len(self.graph.get(dpid, {})) > 2

    # Calcolo dei cammini 
    #BFS
    def _all_shortest_paths(self, src, dst):
        if src == dst:
            return [[src]]
        if src not in self.graph or dst not in self.graph:
            return []
        queue, paths, best = [[src]], [], float("inf")
        while queue:
            path = queue.pop(0)
            if len(path) > best:
                break
            node = path[-1]
            if node == dst:
                paths.append(path)
                best = len(path)
                continue
            for nb in self.graph.get(node, {}):
                if nb not in path:
                    queue.append(path + [nb])
        return paths

    def _spine_on_path(self, path):
        for n in path:
            if self._is_spine(n):
                return n
        return None
    # funzione di decisione del percorso da prendere tra i cammini a costo uguale
    def _pick_path(self, src, dst, training, key):
        """Choose one equal-cost path.

        'balanced': among equal-cost paths, send the flow through the spine that
        currently carries the FEWEST flows of THIS training. A training has Kv
        workers, so its Kv flows split ~Kv/2 per spine -> the inferred Kv drives
        the balancing.

        'single': always the same spine -> the whole training on one path
        (baseline that shows what happens WITHOUT balancing).
        """
        paths = self._all_shortest_paths(src, dst)
        if not paths:
            return None, None

        if training is None:   # non incast traffic (e.g. reverse ACKs)
            return paths[hash(str(key)) % len(paths)], None

        cands = [(self._spine_on_path(p), p) for p in paths]

        if self.routing_mode == "single":
            valid = [(s, p) for s, p in cands if s is not None] or [(None, paths[0])]
            spine, path = min(valid, key=lambda x: x[0] if x[0] is not None else 0)
            return path, spine

        load = self.spine_load[training]
        best = None
        for spine, path in cands:
            l = load[spine] if spine is not None else 0
            if best is None or l < best[0]:
                best = (l, spine, path)
        return best[2], best[1]

    # Caratterizzazione del traffico 
    # ogni round di iperf3 apre una connessione TCP nuova
    def _note_connection(self, training, wip, sport):
        """Called on the first packet of a worker->collector flow."""
        key = (wip, sport)
        if key in self.conn_seen:
            return
        self.conn_seen.add(key)
        now  = time.time()
        last = self.round_start.get(wip)
        if last is None:
            self.phi[wip] = (now - self.global_start) if self.global_start else 0.0
            self.round_start[wip]       = now
            self.first_round_start[wip] = now
            self.round_count[wip]       = 1
            log.debug("[DBG] %s sport=%d  ROUND 1 (phi=%.1fs)",
                      wip, sport, self.phi[wip])
        elif now - last > MIN_ROUND_GAP:
            self.Tv_samples[wip].append(now - last)
            self.round_start[wip] = now
            self.round_count[wip] += 1
            log.debug("[DBG] %s sport=%d  NEW round #%d  gap=%.1fs  samples=%d",
                      wip, sport, self.round_count[wip], now - last,
                      len(self.Tv_samples[wip]))
        else:
            log.debug("[DBG] %s sport=%d  SAME round (gap=%.3fs < %ds)",
                      wip, sport, now - last, MIN_ROUND_GAP)
    #richiesta di statistiche di flusso
    def _request_stats(self):
        for c in core.openflow.connections:
            c.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
    #filtra le statistiche ai soli flussi TCP/IPv4 diretti a un collector noto
    def _handle_FlowStatsReceived(self, event):
        dpid = event.connection.dpid
        here = set()

        for stat in event.stats:
            m = stat.match
            if m.dl_type != 0x0800 or m.nw_proto != 6:
                continue
            if m.nw_dst not in self.collectors:
                continue
            wip = str(m.nw_src)
            key = (wip, m.tp_src)
            here.add(key)
            self.conn_dpids[key].add(dpid)
            # aggiorna il byte_count più alto osservato per questo flusso
            if stat.byte_count > self.conn_bytes.get(key, 0):
                self.conn_bytes[key] = stat.byte_count
            self.worker_training[wip] = self.collectors[m.nw_dst]

        # flussi che questo switch segnalava prima ma non più
        # Only fire "done" when the flow has disappeared from ALL switches that had it.
        for key in list(self.conn_dpids):
            if dpid not in self.conn_dpids[key]:
                continue         # questo switch non lo ha mai avuto, salta
            if key in here:
                continue          #ancora vivo su questo switch
            self.conn_dpids[key].discard(dpid)
            if self.conn_dpids[key]:
                continue         # ancora vivo su almeno un altro switch
            # connessione conclusa (sparito da ogni switch che l'aveva)
            dv = self.conn_bytes.pop(key, 0)
            del self.conn_dpids[key]
            if dv < DV_MIN:
                continue
            wip, _sport = key
            training = self.worker_training.get(wip)
            if training is None:
                continue
            rc = self.round_count[wip]
            # Tv principale: media dei campioni raccolti da _note_connection
            Tv = (sum(self.Tv_samples[wip]) / len(self.Tv_samples[wip])
                  if self.Tv_samples[wip] else None)
            ## Tv di riserva: durata totale / numero di intervalli
            if Tv is None and rc >= 2 and wip in self.first_round_start:
                Tv = ((self.round_start[wip] - self.first_round_start[wip])
                      / (rc - 1))
            log.debug("[DBG] Dv done  worker=%s  Tv_samples=%d  rounds=%d  "
                      "Tv=%s", wip, len(self.Tv_samples[wip]), rc,
                      "%.1fs" % Tv if Tv else "?")
            log.info("[%s] round done | worker=%s | Dv=%.2fMB | Tv=%s | phi_v=%.1fs | rounds=%d",
                     training.upper(), wip, dv / 1e6,
                     "%.1fs" % Tv if Tv else "?",
                     self.phi.get(wip, 0.0),
                     rc)
    
    def _report_distribution(self):
        congested = False
        for t, load in self.spine_load.items():
            kv = len(self.active_workers[t])
            if kv == 0 or not load:
                continue
            parts = " | ".join(f"{dpid_to_str(d)}: {n} flows"
                               for d, n in sorted(load.items()))
            vals = list(load.values())
            if len(vals) < 2:
                status = "[!!] single spine in use"
                congested = True
            else:
                diff  = max(vals) - min(vals)
                ratio = max(vals) / max(1, min(vals))
                if ratio <= UNEVEN_RATIO:
                    status = "[OK] balanced (diff=%d)" % diff
                else:
                    status = "[~] uneven (diff=%d, ratio=%.1f)" % (diff, ratio)
                    congested = True
            log.info("[%s] Kv=%d | %s | %s", t.upper(), kv, parts, status)

        # auto-risparatore da single se rilevato uno squilibrio
        if congested and self.routing_mode == "single":
            self.routing_mode = "balanced"
            log.warning("[AUTO] congestion detected -> switching ROUTING_MODE "
                        "'single' -> 'balanced'")

    # Forwarding
    #MAC learning passivo
    def _handle_PacketIn(self, event):
        pkt = event.parsed
        if not pkt.parsed:
            return
        dpid, in_port = event.dpid, event.port
        src_mac, dst_mac = pkt.src, pkt.dst

        sw_link = any(self.graph.get(dpid, {}).get(nb) == in_port
                      for nb in self.graph.get(dpid, {}))
        if not sw_link and not src_mac.is_multicast:
            self.mac_to_location[src_mac] = (dpid, in_port)
        #metodo di navigazione dei pacchetti incapsulati di POX
        ip4 = pkt.find("ipv4")
        tcp = pkt.find("tcp") if ip4 else None

        # scoperta dei worker e rilevamento dei round
        if ip4 and tcp and ip4.dstip in self.collectors:
            t_name = self.collectors[ip4.dstip]
            wip = ip4.srcip
            if self.global_start is None:
                self.global_start = time.time()
            if wip not in self.active_workers[t_name]:
                self.active_workers[t_name].add(wip)
                if self.training_start_t[t_name] is None:
                    self.training_start_t[t_name] = time.time()
                log.info("[%s] WORKER DISCOVERED %s  Kv=%d",
                         t_name.upper(), wip, len(self.active_workers[t_name]))
            self._note_connection(t_name, str(wip), tcp.srcport)
        #se la destinazione non e ancora nota si fa flood
        if dst_mac.is_multicast or dst_mac not in self.mac_to_location:
            self.flood_to_hosts(event)
            return

        dst_dpid, dst_port = self.mac_to_location[dst_mac]

        is_incast = bool(ip4 and ip4.dstip in self.collectors)
        training  = self.collectors[ip4.dstip] if is_incast else None
        ecmp_key  = ip4.srcip if ip4 else src_mac
        path, spine = self._pick_path(dpid, dst_dpid, training, ecmp_key)
        if path is None:
            self.flood_to_hosts(event)
            return

        if is_incast and spine is not None:
            self.spine_load[training][spine] += 1
            log.info("[%s] flow %s via spine %s  (load: %s)",
                     training.upper(), ip4.srcip, dpid_to_str(spine),
                     " ".join(f"{dpid_to_str(d)}:{n}"
                              for d, n in sorted(self.spine_load[training].items())))

        for i in range(len(path)):
            node = path[i]
            op   = dst_port if node == dst_dpid else self.graph[node][path[i + 1]]
            msg  = of.ofp_flow_mod()
            msg.match.dl_type = pkt.type
            msg.match.dl_src  = src_mac
            msg.match.dl_dst  = dst_mac
            if ip4:
                msg.match.nw_src = ip4.srcip
                msg.match.nw_dst = ip4.dstip
                if tcp:
                    msg.match.nw_proto = 6
                    msg.match.tp_src   = tcp.srcport
                    msg.match.tp_dst   = tcp.dstport
            msg.actions.append(of.ofp_action_output(port=op))
            msg.idle_timeout = IDLE_TIMEOUT
            msg.hard_timeout = HARD_TIMEOUT
            conn = core.openflow.getConnection(node)
            if conn:
                conn.send(msg)

        op_first = dst_port if dpid == dst_dpid else self.graph[dpid][path[1]]
        m2 = of.ofp_packet_out()
        m2.data = event.ofp
        m2.in_port = in_port
        m2.actions.append(of.ofp_action_output(port=op_first))
        event.connection.send(m2)
    #manda il pacchetto grezzo fuori da ogni porta di ogni switch
    def flood_to_hosts(self, event):
        raw = event.parsed.pack()
        for conn in core.openflow.connections:
            dpid = conn.dpid
            out_ports = [p for p in conn.ports if p <= of.OFPP_MAX
                         and not any(self.graph.get(dpid, {}).get(nb) == p
                                     for nb in self.graph.get(dpid, {}))
                         and not (dpid == event.dpid and p == event.port)]
            if out_ports:
                msg = of.ofp_packet_out()
                msg.data = raw
                msg.buffer_id = None
                msg.in_port = of.OFPP_NONE
                for p in out_ports:
                    msg.actions.append(of.ofp_action_output(port=p))
                conn.send(msg)

#punto di ingresso del modulo POX
def launch():
    core.registerNew(MLRoutingApp)