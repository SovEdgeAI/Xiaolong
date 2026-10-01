package us.fiu.adwise.approach2;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import us.fiu.adwise.approach2.common.FabricDeviceConfig;
import us.fiu.adwise.approach2.pipeconf.PipeconfLoader;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
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
//Ioexception
import java.io.IOException;
import java.io.OutputStream;


@Component(immediate = true)
public class UpdateFlowStats {
    private static final Logger log = LoggerFactory.getLogger(UpdateFlowStats.class);
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
    public static List<FlowRule> blockedFlowRules = MitigationModule.getBlockedFlowRules();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("us.fiu.adwise.approach2.UpdateFlowStats");
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        packetService.requestPackets(selector, PacketPriority.REACTIVE, appId);
        scheduledExecutor = Executors.newScheduledThreadPool(1);
        scheduledExecutor.scheduleAtFixedRate(new InnerUpdateFlowStats(), 0, 5, TimeUnit.SECONDS);
        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        if (scheduledExecutor != null) {
            scheduledExecutor.shutdown();
        }

        log.info("Stopped");
    }

    private class InnerUpdateFlowStats implements Runnable {
        @Override
        public void run() {
            updateFlowStats();
        }
    }

    private void updateFlowStats() {
        // Define regex patterns for extracting packets and bytes
        Pattern packetsPattern = Pattern.compile("packets=(\\d+)");
        Pattern bytesPattern = Pattern.compile("bytes=(\\d+)");
        int packets = 0;
        int bytes = 0;
        //Remove all the blocked flow rules
        flowRules.removeAll(blockedFlowRules);
    
        Iterable<FlowEntry> flowEntries = flowRuleService.getFlowEntries(deviceId);
        for (FlowEntry entry : flowEntries) {
            if (entry.table().toString().equals("IngressPipeImpl.gtp_flows")) {
                String flowEntryString = entry.toString();
                // Create FlowDetails object and add to the list
                String srcIpAddress = convertHexToIPv4(extractValue(entry.selector().toString(), "hdr.inner_ipv4.src_addr=(\\S+)"));
                String dstIpAddress = convertHexToIPv4(extractValue(entry.selector().toString(), "hdr.inner_ipv4.dst_addr=(\\S+)"));
                String protocol = String.valueOf(Integer.parseInt(extractValue(entry.selector().toString(), "hdr.inner_ipv4.protocol=(\\S+)").substring(2), 16));
                int protocolInt = Integer.parseInt(protocol);
                // Extract the packet and byte counts from the flow entry
                Matcher packetsMatcher = packetsPattern.matcher(flowEntryString);
                Matcher bytesMatcher = bytesPattern.matcher(flowEntryString);
                if (packetsMatcher.find()) {
                    String packetsString = packetsMatcher.group(1);
                    packets = Integer.parseInt(packetsString);
                } else {
                    log.warn("Packets not found in flow entry string");
                }
    
                if (bytesMatcher.find()) {
                    String bytesString = bytesMatcher.group(1);
                    bytes = Integer.parseInt(bytesString);
                } else {
                    log.warn("Bytes not found in flow entry string");
                }
                
                updateDB(srcIpAddress, dstIpAddress, protocolInt, bytes, packets);
            }
        }
    }
    
    private static String prepareJsonData(int length, int packets) {
        return String.format("{ \"bytes\": %d , \"packets\": %d }", length, packets);
    }

    private void sendFlowMessagesToServer(String flowString) {
        try {
            // Convert the results to a JSON format
            String jsonResults = "{ \"Data\": \"" + flowString + "\" }";

            Socket socket = new Socket(AppConstants.APP_HOST, 7000);
            OutputStream outputStream = socket.getOutputStream();
            outputStream.write(jsonResults.getBytes());

            // Receive a response from the server (in this case, "1")
            InputStream inputStream = socket.getInputStream();
            byte[] responseBuffer = new byte[1];
            int bytesRead = inputStream.read(responseBuffer);

            socket.close();
        } catch (IOException e) {
            log.error("Error sending flow messages to the server", e);
        }
    }


    
    private void updateDB(String srcIp, String dstIp, int protocol, int length, int packets) {
        try {
            String putUrl = "http://" + AppConstants.APP_HOST + ":23500/flow/"+srcIp+"-"+dstIp+"-"+protocol;
            URL url = new URL(putUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("PUT");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            String jsonData = prepareJsonData(length, packets);
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
                InputStream errorStream = connection.getErrorStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(errorStream));
                String line;
                StringBuilder response = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                log.info("Server error message: " + response.toString());
            }
            connection.disconnect();
        } catch (Exception e) {
            log.info("Exception occurred while posting flows: " + e.getMessage());
            e.printStackTrace();  // Print the stack trace for more detailed error information
        }
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

    // Add the convertHexToDecimal method here (if you haven't added it already)
    private String convertHexToDecimal(String hexValue) {
        try {
            // Check if the input string is valid
            if (hexValue == null || hexValue.length() < 3 || !hexValue.startsWith("0x")) {
                log.error("Error: Invalid hexadecimal input");
                return null;
            }

            // Convert hexadecimal to decimal and store as string
            return Integer.toString(Integer.parseInt(hexValue.substring(2), 16));
        } catch (NumberFormatException e) {
            log.error("Error: Unable to convert hex to decimal - " + e.getMessage());
            return null;
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

}