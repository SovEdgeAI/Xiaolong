/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package us.fiu.adwise.approach2.pipeconf;

import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.driver.DriverAdminService;
import org.onosproject.net.driver.DriverProvider;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Optional;


import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.BMV2_JSON;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.P4_INFO_TEXT;
import static us.fiu.adwise.approach2.AppConstants.PIPECONF_ID;

/**
 * Component that builds and register the pipeconf at app activation.
 */
@Component(immediate = true, service = PipeconfLoader.class)
public final class PipeconfLoader {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private static final String P4INFO_PATH = "/onos-p4-gtp.p4info.txt";
    private static final String BMV2_JSON_PATH = "/onos-p4-gtp.json";


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private PiPipeconfService pipeconfService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DriverAdminService driverAdminService;

    @Activate
    public void activate() {
        // Registers the pipeconf at component activation.
        log.info("Registers the pipeconf at component activation.");
        log.info("Pipeconfig ID: {}", PIPECONF_ID);


        if (pipeconfService.getPipeconf(PIPECONF_ID).isPresent()) {
            // Remove first if already registered, to support reloading of the
            // pipeconf during the tutorial.
            pipeconfService.unregister(PIPECONF_ID);
        }
        removePipeconfDrivers();
        try {
            PiPipeconf registeredPipeconf = buildPipeconf();
            pipeconfService.register(registeredPipeconf);
        } catch (P4InfoParserException e) {
            log.error("Unable to register " + PIPECONF_ID, e);
        }

        getPipedetails();
        

    }

    @Deactivate
    public void deactivate() {
        // Do nothing.
    }

    private PiPipeconf buildPipeconf() throws P4InfoParserException {
        final URL p4InfoUrl = PipeconfLoader.class.getResource(P4INFO_PATH);
        final URL bmv2JsonUrlUrl = PipeconfLoader.class.getResource(BMV2_JSON_PATH);
        final PiPipelineModel pipelineModel = P4InfoParser.parse(p4InfoUrl);
        log.info("returning DefaultPiPipeconf.builder()");
        
        return DefaultPiPipeconf.builder()
                .withId(PIPECONF_ID)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, InterpreterImpl.class)
                .addBehaviour(Pipeliner.class, PipelinerImpl.class)
                .addExtension(P4_INFO_TEXT, p4InfoUrl)
                .addExtension(BMV2_JSON, bmv2JsonUrlUrl)
                .build();
    }

    private void removePipeconfDrivers() {
        List<DriverProvider> driverProvidersToRemove = driverAdminService
                .getProviders().stream()
                .filter(p -> p.getDrivers().stream()
                        .anyMatch(d -> d.name().endsWith(PIPECONF_ID.id())))
                .collect(Collectors.toList());
        
        if (driverProvidersToRemove.isEmpty()) {
            return;
        }

        log.info("Found {} outdated drivers for pipeconf '{}', removing...",
                 driverProvidersToRemove.size(), PIPECONF_ID);

        driverProvidersToRemove.forEach(driverAdminService::unregisterProvider);
    }

    private void getPipedetails() {        
        Optional<PiPipeconf> pipeconf = pipeconfService.getPipeconf(PIPECONF_ID);
        
        if (pipeconf.isPresent()) {
            PiPipeconf piPipeconf = pipeconf.get();
            // Access other details of the pipeline model as needed
            logActionProfiles(piPipeconf.pipelineModel());
            logCounters(piPipeconf.pipelineModel());
            logMeters(piPipeconf.pipelineModel());
            logTables(piPipeconf.pipelineModel());
            // You can add similar log statements for other pipeline components
    
        } else {
        }
    }
    
    // Helper methods to log details of different pipeline components
    private void logActionProfiles(PiPipelineModel pipelineModel) {
        pipelineModel.actionProfiles().forEach(actionProfile -> {
            // Add more logging for action profile details as needed
        });
    }
    
    private void logCounters(PiPipelineModel pipelineModel) {
        pipelineModel.counters().forEach(counter -> {

            // Add more logging for counter details as needed
        });
    }
    
    private void logMeters(PiPipelineModel pipelineModel) {
        pipelineModel.meters().forEach(meter -> {
            // Add more logging for meter details as needed
        });
    }
    
    private void logTables(PiPipelineModel pipelineModel) {
        pipelineModel.tables().forEach(table -> {
            // Add more logging for table details as needed
        });
    }
    
}
