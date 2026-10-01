package us.fiu.adwise.approach2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

import us.fiu.adwise.approach2.DetectionModule;
import us.fiu.adwise.approach2.common.FabricDeviceConfig;
import us.fiu.adwise.approach2.pipeconf.PipeconfLoader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;
import org.onlab.packet.Ethernet;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TableId;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.config.ConfigFactory;
import static us.fiu.adwise.approach2.AppConstants.PIPECONF_ID;
import static us.fiu.adwise.approach2.AppConstants.APP_NAME;
import static us.fiu.adwise.approach2.AppConstants.CLEAN_UP_DELAY;
import static us.fiu.adwise.approach2.AppConstants.DEFAULT_CLEAN_UP_RETRY_TIMES;
import static us.fiu.adwise.approach2.common.Utils.sleep;
import us.fiu.adwise.approach2.common.Utils;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.net.pi.service.PiPipeconfService;    
import org.onosproject.net.packet.PacketService;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ScheduledExecutorService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
// IOException
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

@Component(immediate = true)
public class MitigationModule {
    private static final Logger log = LoggerFactory.getLogger(MitigationModule.class);

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private DeviceId deviceId = DeviceId.deviceId("device:s1");
    private ScheduledExecutorService scheduledExecutor;

    // FlowRule List

    public static List<String> flaggedIps = DetectionModule.getFlaggedIps();
    public static List<FlowRule> flowRules = CreateGTPFlows.getFlowRules();
    public static List<FlowRule> blockedFlowRules = new ArrayList<>();

    // Block reconciliation.
    //
    // The flow API's /blocked-ips collection is the source of truth for which
    // UEs are blocked; this component makes the switch match it every tick.
    // Before this existed, a drop rule was only installed as a side effect of
    // the detector flagging an IP that also had a live gtp_flows rule in memory,
    // so (a) POST /blocked-ip/<ip> by hand did nothing, (b) DELETE never removed
    // the rule, and (c) every ONOS restart silently unblocked everyone while the
    // DB still listed them as blocked.
    private final Map<String, FlowRule> installedBlocks =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static final Pattern BLOCKED_IP =
            Pattern.compile("\"ueip\":\"([0-9]+(?:\\.[0-9]+){3})\"");


    @Activate
    protected void activate() {
        appId = coreService.registerApplication("us.fiu.adwise.approach2.MitigationModule");
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
        scheduledExecutor = Executors.newScheduledThreadPool(1);
        scheduledExecutor.scheduleAtFixedRate(new RunnableMitigationModule(), 0, 5, TimeUnit.SECONDS);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        scheduledExecutor.shutdown();
        log.info("Stopped");
        //Clean the list of flagged IPs
        flaggedIps.clear();
        flowRules.clear();
        blockedFlowRules.clear();
    }

    public static List<FlowRule> getBlockedFlowRules() {
        return blockedFlowRules;
    }



    private class RunnableMitigationModule implements Runnable {
        @Override
        public void run() {
            try {
                mitigationModuleMethod();
            } catch (IOException | InterruptedException e) {
                log.error("Error in detection module method", e);
            }
        }
    }

    private void mitigationModuleMethod() throws IOException, InterruptedException {
        String flaggedIp = "";
        List<FlowRule> toRemove = new ArrayList<>();
        for(FlowRule flowRule : flowRules) {
            String srcIpAddress = convertHexToIPv4(extractValue(flowRule.selector().toString(), "hdr.inner_ipv4.src_addr=(\\S+)"));
            String dstIpAddress = convertHexToIPv4(extractValue(flowRule.selector().toString(), "hdr.inner_ipv4.dst_addr=(\\S+)"));
            String protocol = String.valueOf(Integer.parseInt(extractValue(flowRule.selector().toString(), "hdr.inner_ipv4.protocol=(\\S+)").substring(2), 16));
            //Check which one starts with 10.45.0
            if(flaggedIps.contains(srcIpAddress) || flaggedIps.contains(dstIpAddress)) {
                flaggedIp = srcIpAddress.startsWith("10.45.0") ? srcIpAddress : dstIpAddress;
                // flaggedIp = flaggedIp.equals(srcIpAddress) ? srcIpAddress : dstIpAddress;
                flowRuleService.removeFlowRules(flowRule);
                // transfer the flow rule to the blocked flow rules list
                blockedFlowRules.add(flowRule);
            }   
        }
        if(!flaggedIp.equals("")) {
            final FlowRule blockedIp = buildBlockRule(flaggedIp);
            flowRuleService.applyFlowRules(blockedIp);
            installedBlocks.put(flaggedIp, blockedIp);
            flaggedIps.remove(flaggedIp);
        }
        reconcileBlockedIps();
    }

    /** Drop rule for one UE: exact match on the GTP inner source address. */
    private FlowRule buildBlockRule(String ueIp) {
        final PiCriterion piCriterion = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.inner_ipv4.src_addr"), ipAddressToBytes(ueIp))
                .build();
        final PiAction drop = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.drop"))
                .build();
        // Utils.buildFlowRule is deterministic (fixed priority, permanent), so
        // re-applying the same IP yields the same FlowRule id: idempotent.
        return Utils.buildFlowRule(deviceId, appId, "IngressPipeImpl.dropped_inner_ipv4", piCriterion, drop);
    }

    /** Makes the switch's drop rules match /blocked-ips: install missing, remove stale. */
    private void reconcileBlockedIps() {
        java.util.Set<String> desired = new java.util.HashSet<>();
        try {
            HttpResponse<String> resp = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://" + AppConstants.APP_HOST + ":23500/blocked-ips"))
                            .GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                // Never treat an unreachable API as "nobody is blocked".
                return;
            }
            Matcher m = BLOCKED_IP.matcher(resp.body());
            while (m.find()) {
                desired.add(m.group(1));
            }
        } catch (Exception e) {
            log.warn("Block reconcile skipped, flow API unreachable: {}", e.getMessage());
            return;
        }

        // Compare against what ONOS actually holds, not against what was sent.
        // A rule applied before device:s1 exists (06_deploy_app.sh activates the
        // app before pushing the netcfg that creates the device) is silently
        // discarded; trusting installedBlocks alone would then never retry it.
        java.util.Set<org.onosproject.net.flow.FlowId> present = new java.util.HashSet<>();
        for (FlowEntry e : flowRuleService.getFlowEntriesById(appId)) {
            present.add(e.id());
        }
        for (String ip : desired) {
            FlowRule rule = installedBlocks.computeIfAbsent(ip, this::buildBlockRule);
            if (!present.contains(rule.id())) {
                flowRuleService.applyFlowRules(rule);
                log.info("Block: installed dropped_inner_ipv4 for {}", ip);
            }
        }
        for (String ip : new ArrayList<>(installedBlocks.keySet())) {
            if (!desired.contains(ip)) {
                flowRuleService.removeFlowRules(installedBlocks.remove(ip));
                log.info("Block: removed dropped_inner_ipv4 for {}", ip);
            }
        }
    }

    
    private void sendFlowMessagesToServer(String flowString) throws IOException {
        // Convert the results to a JSON format
        String jsonResults = "{ \"Data\": \"" + flowString + "\" }";

        try (Socket socket = new Socket(AppConstants.APP_HOST, 7000);
             OutputStream outputStream = socket.getOutputStream();
             InputStream inputStream = socket.getInputStream()) {

            outputStream.write(jsonResults.getBytes());

            // Receive a response from the server (in this case, "1")
            byte[] responseBuffer = new byte[1];
            int bytesRead = inputStream.read(responseBuffer);
        }

    }

    
    public String extractValue(String input, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        if (matcher.find()) {
            // Get the matched group (index 1) and remove commas, square brackets, and curly braces
            String extractedValue = matcher.group(1).replaceAll(",", "")
                                                      .replaceAll("\\]", "")
                                                      .replaceAll("\\}", "");
            return extractedValue;
        }
        return null;
    }

    public static String convertHexToIPv4(String hexValue) {
        try {
            // Parse the hexadecimal string and convert it to decimal
            long decimalValue = Long.parseLong(hexValue.substring(2), 16);

            // Extract octets from the decimal value
            int octet1 = (int) ((decimalValue >> 24) & 0xFF);
            int octet2 = (int) ((decimalValue >> 16) & 0xFF);
            int octet3 = (int) ((decimalValue >> 8) & 0xFF);
            int octet4 = (int) (decimalValue & 0xFF);

            // Construct the IPv4 address string
            String ipv4Address = octet1 + "." + octet2 + "." + octet3 + "." + octet4;
            return ipv4Address;
        } catch (NumberFormatException e) {
            // Handle exception if conversion fails
            return null;
        }
    }

    private static byte[] ipAddressToBytes(String ipAddress) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ipAddress);
            return inetAddress.getAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }



    
}
