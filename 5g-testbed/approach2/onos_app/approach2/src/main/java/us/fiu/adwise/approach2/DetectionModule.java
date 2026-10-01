package us.fiu.adwise.approach2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
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

import javax.print.DocFlavor.SERVICE_FORMATTED;

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
public class DetectionModule {
    private static final Logger log = LoggerFactory.getLogger(DetectionModule.class);

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
    public static List<FlowRule> flowRules = CreateGTPFlows.getFlowRules();
    public static List<String> flaggedIps = new ArrayList<>();



    @Activate
    protected void activate() {
        appId = coreService.registerApplication("us.fiu.adwise.approach2.DetectionModule");
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
        scheduledExecutor = Executors.newScheduledThreadPool(1);
        scheduledExecutor.scheduleAtFixedRate(new RunnableDetectionModule(), 0, 5, TimeUnit.SECONDS);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        scheduledExecutor.shutdown();
        log.info("Stopped");
    }

    private class RunnableDetectionModule implements Runnable {
        @Override
        public void run() {
            try {
                detectionModuleMethod();
            } catch (IOException | InterruptedException e) {
                log.error("Error in detection module method", e);
            }
        }
    }

    public static List<String> getFlaggedIps() {
        return flaggedIps;
    }
    private void detectionModuleMethod() throws IOException, InterruptedException {
        // Create an HttpClient instance
        HttpClient client = HttpClient.newHttpClient();

        // Create a GET request to a specific URL
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://" + AppConstants.APP_HOST + ":23500/flaggedIps/top"))
                .GET()
                .build();

        // Send the request and receive a response
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String regex = "\"ueip\":\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\"";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(response.body());
        String flaggedIp = "";
        if(matcher.find()){
            sendFlowMessagesToServer("DETECTIONMODULE");
            sendFlowMessagesToServer(matcher.group(1));
            flaggedIp = matcher.group(1);
            //Delete the ip from the db
            HttpClient client2 = HttpClient.newHttpClient();
            HttpRequest request2 = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + AppConstants.APP_HOST + ":23500/flagged-ips/" + flaggedIp))
                    .DELETE()
                    .build();

            // Send the request and do not receive a response
            client2.send(request2, HttpResponse.BodyHandlers.discarding());

            HttpClient client3 = HttpClient.newHttpClient();
            HttpRequest request3 = HttpRequest.newBuilder()
            .uri(URI.create("http://" + AppConstants.APP_HOST + ":23500/blocked-ip/" + flaggedIp))
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();

            // Send the request and do not receive a response
            client3.send(request3, HttpResponse.BodyHandlers.discarding());
        }
        //Check if the flagged IP is already in the list
        if (!flaggedIps.contains(flaggedIp)) {
            flaggedIps.add(flaggedIp);
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

    private void updateDB(String srcIp, String dstIp, int protocol, int length, int packets) {
        try {
            String putUrl = "http://" + AppConstants.APP_HOST + ":23500/flow/" + srcIp + "-" + dstIp + "-" + protocol;
            String jsonData = prepareJsonData(length, packets);

            HttpURLConnection connection = (HttpURLConnection) new URL(putUrl).openConnection();
            connection.setRequestMethod("PUT");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonData.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                log.info("Flow data posted successfully.");
            } else {
                log.info("Failed to post flow data. HTTP Response Code: " + responseCode);
                // Read the error message from the server
                try (InputStream errorStream = connection.getErrorStream();
                     BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream))) {

                    String line;
                    StringBuilder response = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    log.info("Server error message: " + response.toString());
                }
            }
            connection.disconnect();
        } catch (IOException e) {
            log.error("Exception occurred while posting flows: " + e.getMessage(), e);
        }
    }

    private static String prepareJsonData(int length, int packets) {
        return String.format("{ \"bytes\": %d , \"packets\": %d }", length, packets);
    }

    public static String convertHexToIPv4(String hexValue) {
        try {
            // Parse the hexadecimal string and convert it to decimal
            long decimalValue = Long.parseLong(hexValue.substring(2), 16);

            // Extract octets from the decimal value
            String ip = String.format("%d.%d.%d.%d",
                    (decimalValue >> 24) & 0xFF,
                    (decimalValue >> 16) & 0xFF,
                    (decimalValue >> 8) & 0xFF,
                    decimalValue & 0xFF);

            return ip;
        } catch (NumberFormatException e) {
            log.error("Invalid hex value: " + hexValue, e);
            return "Invalid IP";
        }
    }
}
