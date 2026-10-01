/*
 * Per-flow bandwidth control for the approach2 P4 pipeline.
 *
 * onos-p4-gtp.p4 attaches an indirect meter (gtp_flow_meter) to the gtp_flows
 * table, and track_gtp_flows carries an `index` selecting that flow's meter
 * cell. This component writes the rate into a cell, so a single GTP *inner* IP
 * flow can be policed independently of every other flow sharing the same
 * gNB<->UPF tunnel.
 *
 * This is the capability an OVS/OpenFlow pipeline cannot provide: OVS has no
 * GTP parser, so it can only police the aggregate tunnel.
 *
 * Control surface: two files inside the ONOS container, polled once a second.
 *   /tmp/qos_rate_kbps    rate to apply, in kbps; 0 or absent removes the limit
 *   /tmp/qos_meter_index  meter cell to apply it to; "all" for every known cell
 * A file is used rather than a REST endpoint so the limit can be changed
 * mid-experiment with a plain `docker exec` and no extra service.
 */
package us.fiu.adwise.approach2;

import org.onosproject.net.DeviceId;
import org.onosproject.net.pi.model.PiMeterId;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiMeterBand;
import org.onosproject.net.pi.runtime.PiMeterCellConfig;
import org.onosproject.net.pi.runtime.PiMeterCellId;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.api.P4RuntimeController;
import org.onosproject.p4runtime.api.P4RuntimeClient;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component(immediate = true, service = QoSMeterModule.class)
public class QoSMeterModule {

    private static final Logger log = LoggerFactory.getLogger(QoSMeterModule.class);

    private static final DeviceId DEVICE_ID = DeviceId.deviceId("device:s1");
    // device_id from bash_scripts/netcfg.json (grpc://localhost:50001?device_id=1)
    private static final long P4_DEVICE_ID = 1;
    private static final PiMeterId METER_ID =
            PiMeterId.of("IngressPipeImpl.gtp_flow_meter");

    private static final Path RATE_FILE = Paths.get("/tmp/qos_rate_kbps");
    private static final Path INDEX_FILE = Paths.get("/tmp/qos_meter_index");

    // An unset cell must not police, so "no limit" is expressed as a rate large
    // enough never to be the bottleneck rather than by deleting the cell.
    private static final long UNLIMITED_BYTES_PER_SEC = 12_500_000_000L; // 100 Gbit/s

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected P4RuntimeController p4RuntimeController;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PiPipeconfService pipeconfService;

    private ScheduledExecutorService executor;
    private String lastApplied = "";

    @Activate
    protected void activate() {
        executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(this::poll, 5, 1, TimeUnit.SECONDS);
        log.info("QoSMeterModule started; watching {} and {}", RATE_FILE, INDEX_FILE);
    }

    @Deactivate
    protected void deactivate() {
        if (executor != null) {
            executor.shutdownNow();
        }
        log.info("QoSMeterModule stopped");
    }

    private String readFile(Path p, String fallback) {
        try {
            return Files.exists(p) ? new String(Files.readAllBytes(p)).trim() : fallback;
        } catch (Exception e) {
            return fallback;
        }
    }

    /** Re-applies the requested limit whenever the control files change. */
    private void poll() {
        try {
            String rateStr = readFile(RATE_FILE, "0");
            String idxStr = readFile(INDEX_FILE, "all");
            String desired = rateStr + "@" + idxStr;
            if (desired.equals(lastApplied)) {
                return;
            }

            long kbps;
            try {
                kbps = Long.parseLong(rateStr);
            } catch (NumberFormatException e) {
                log.warn("QoS: bad rate '{}', ignoring", rateStr);
                return;
            }

            Map<String, Integer> table = CreateGTPFlows.meterIndexTable();
            if (table.isEmpty()) {
                // No flows learned yet; retry on the next tick.
                return;
            }

            boolean ok = true;
            if ("all".equalsIgnoreCase(idxStr)) {
                for (Integer idx : table.values()) {
                    ok &= applyRate(idx, kbps);
                }
            } else {
                ok = applyRate(Integer.parseInt(idxStr), kbps);
            }

            if (ok) {
                lastApplied = desired;
                log.info("QoS: applied {} kbps to meter cell(s) {}",
                         kbps == 0 ? "unlimited" : kbps, idxStr);
            }
        } catch (Exception e) {
            log.warn("QoS poll failed: {}", e.getMessage());
        }
    }

    /** Writes one meter cell. rateKbps == 0 means "remove the limit". */
    public boolean applyRate(int index, long rateKbps) {
        Optional<PiPipeconf> pipeconf = pipeconfService.getPipeconf(AppConstants.PIPECONF_ID);
        if (!pipeconf.isPresent()) {
            log.warn("QoS: pipeconf {} not registered", AppConstants.PIPECONF_ID);
            return false;
        }
        P4RuntimeClient client = p4RuntimeController.get(DEVICE_ID);
        if (client == null) {
            log.warn("QoS: no P4Runtime client for {}", DEVICE_ID);
            return false;
        }

        // The meter is declared with MeterType.bytes, so rate is bytes/second.
        long bytesPerSec = rateKbps == 0
                ? UNLIMITED_BYTES_PER_SEC
                : (rateKbps * 1000L) / 8L;
        // A burst that is too small makes TCP collapse well below the setpoint;
        // 100 ms of the configured rate is the usual rule of thumb.
        long burstBytes = Math.max(bytesPerSec / 10L, 3000L);

        // P4Runtime meters carry two bands: committed (CIR) and peak (PIR).
        PiMeterCellConfig config = PiMeterCellConfig.builder()
                .withMeterCellId(PiMeterCellId.ofIndirect(METER_ID, index))
                .withMeterBand(new PiMeterBand(bytesPerSec, burstBytes))
                .withMeterBand(new PiMeterBand(bytesPerSec, burstBytes))
                .build();

        try {
            boolean success = client.write(P4_DEVICE_ID, pipeconf.get())
                    .modify(config)
                    .submitSync()
                    .isSuccess();
            if (!success) {
                log.warn("QoS: write to meter cell {} was rejected", index);
            }
            return success;
        } catch (Exception e) {
            log.error("QoS: failed writing meter cell {}: {}", index, e.getMessage());
            return false;
        }
    }
}
