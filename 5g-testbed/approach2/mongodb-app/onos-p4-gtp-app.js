// app.js

// Node 18 does not expose the WebCrypto API as a global when running a script
// file, but the MongoDB driver's uuidV4() calls a bare `crypto.getRandomValues`
// on every session, which throws "crypto is not defined" on each query. Node 19+
// defines this global already, so this is a no-op there.
if (typeof globalThis.crypto === 'undefined') {
    globalThis.crypto = require('node:crypto').webcrypto;
}

const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();
const PORT = 23500; // You can use any port you prefer

const cors = require('cors');
const e = require('express');
app.use(cors());

// Add this middleware to parse JSON in the request body
app.use(express.json());

app.use(bodyParser.json());
// Was hardcoded to the original lab machine (10.102.196.198:27018). Defaults to
// a local MongoDB on the standard port; override with MONGO_URI.
// useNewUrlParser/useUnifiedTopology were removed in the MongoDB driver v4+
// and now throw MongoParseError, so they are no longer passed.
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/onos-p4-flows';
mongoose.connect(MONGO_URI);
mongoose.connection.on('connected', () => console.log(`MongoDB connected: ${MONGO_URI}`));
mongoose.connection.on('error', (err) => console.error('MongoDB error:', err.message));


// Schema Definitions 


// Flow Schema 
const flowSchema = new mongoose.Schema({
    _id: { type: String, required: true, alias: 'flowId' },
    type: { type: String},
    srcIp : { type: String},
    dstIp : { type: String},
    durationInMicroseconds : { type: Number, default: 0 },
    duration : { type: Number, default: 0 },
    packets : { type: Number, default: 0 },
    oldpackets : { type: Number, default: 0 },
    bytes : { type: Number, default: 0},
    oldbytes : { type: Number, default: 0},
    protocol : { type: String },
    CreatedAt: { type: Date, default: Date.now },
}, {_id: false});

const Flow = mongoose.model('Flow', flowSchema);

const queueSchema = {
    type: [Number],
    default: [0, 0, 0, 0, 0],
    validate: {
        validator: function (v) {
            return v.length <= 5;
        },
        message: props => `${props.value} exceeds the limit of 5 elements for the queue!`
    }
};

//Unidirectional Flow Schema
const unidirectionalFlowSchema = new mongoose.Schema({
    _id: { type: String, required: true, alias: 'flowId' },
    fwdFlow : flowSchema,
    bwdFlow : flowSchema,
    flowBytesPerSecond : { type: Number, default: 0 },
    flowPacketsPerSecond : { type: Number, default: 0 },
    bwdPacketsPerSecond : { type: Number, default: 0 },
    fwdPacketsPerSecond : { type: Number, default: 0 },
    bwdPacketLengthMax : { type: Number, default: 0 },
    fwdPacketLengthMax : { type: Number, default: 0 },
    bwdPacketLengthMin : { type: Number, default: 0 },
    fwdPacketLengthMin : { type: Number, default: 0 },
    nbPredicitionQueue : queueSchema,
    lrPredictionQueue : queueSchema,
    nbPredictionAvg : { type: Number, default: 0 },
    lrPredictionAvg : { type: Number, default: 0 }
}); 

const UnidirectionalFlow = mongoose.model('UnidirectionalFlow', unidirectionalFlowSchema);


// Define the Mongoose schema
const blockedIPSchema = new mongoose.Schema({
    _id: { type: String, required: true, alias: 'blockedip' },
    ueip: { type: String },
    CreatedAt: { type: Date, default: Date.now }
  });
  
  const BlockedUEIP = mongoose.model('BlockedIp', blockedIPSchema);


  // Define the Mongoose schema
const flaggedIPSchema = new mongoose.Schema({
    _id: { type: String, required: true, alias: 'flaggedip' },
    ueip: { type: String },
    CreatedAt: { type: Date, default: Date.now }
  });
  
  const flaggedUEIP = mongoose.model('FlaggedIP', flaggedIPSchema);
  
//REST API 

//Update flow

// The UE address pool configured on the SMF/UPF (10.45.0.0/16). Uplink - UE to
// DN - is the "forward" direction everywhere in this system.
const UE_POOL_PREFIX = process.env.UE_POOL_PREFIX || '10.45.';
function isUeAddress(ip) {
    return typeof ip === 'string' && ip.startsWith(UE_POOL_PREFIX);
}

async function createNewFlow(flowId, type, bytes, packets) {
    const [srcIp, dstIp, protocol] = flowId.split('-');

    const forwardFlow = new Flow({
        _id: srcIp + "-" + dstIp + "-" + protocol,
        type: type,
        srcIp: srcIp,
        dstIp: dstIp,
        protocol: protocol,
        bytes: bytes,
        packets: packets,
    });

    const backwardFlow = new Flow({
        _id: dstIp + "-" + srcIp + "-" + protocol,
        type: type === "forward" ? "backward" : "forward",
        srcIp: dstIp,
        dstIp: srcIp,
        protocol: protocol,
        bytes: 0,
        packets: 0,
    });

    const unidirectionalFlow = new UnidirectionalFlow({
        _id: srcIp + "<->" + dstIp + "<->" + protocol,
        fwdFlow: forwardFlow,
        bwdFlow: backwardFlow,
        fwdPacketLengthMax: bytes,
        fwdPacketLengthMin: bytes,
    });

    await Promise.all([forwardFlow.save(), backwardFlow.save(), unidirectionalFlow.save()]);
    return forwardFlow; // Return the forwardFlow for further processing if needed
}

async function updateUnidirectionalFlow(flow, unidirectionalFlow, bytes, packets) {
    if (bytes === 0 && packets === 0) {
        return;
    }

    const isForward = flow.type === "forward";
    const fwdOrBwd = isForward ? "fwd" : "bwd";

    //update the old bytes and packets
    unidirectionalFlow[fwdOrBwd + "Flow"].oldbytes = unidirectionalFlow[fwdOrBwd + "Flow"].bytes;
    unidirectionalFlow[fwdOrBwd + "Flow"].oldpackets = unidirectionalFlow[fwdOrBwd + "Flow"].packets;

    //Get an average of the bytes and packets to calculate the packet length
    const avgPacketSize = (bytes - unidirectionalFlow[fwdOrBwd + "Flow"].oldbytes) / (packets - unidirectionalFlow[fwdOrBwd + "Flow"].oldpackets);
    // const avgBytes = (unidirectionalFlow[fwdOrBwd + "Flow"].bytes + bytes) / (unidirectionalFlow[fwdOrBwd + "Flow"].packets + packets);8.8.8.8


    if (unidirectionalFlow[fwdOrBwd + "PacketLengthMax"] === 0 && unidirectionalFlow[fwdOrBwd + "PacketLengthMin"] === 0) {
        unidirectionalFlow[fwdOrBwd + "PacketLengthMax"] = avgPacketSize;
        unidirectionalFlow[fwdOrBwd + "PacketLengthMin"] = avgPacketSize;
    } else {
        if (avgPacketSize > unidirectionalFlow[fwdOrBwd + "PacketLengthMax"]) {
            unidirectionalFlow[fwdOrBwd + "PacketLengthMax"] = avgPacketSize;
        }
        if (avgPacketSize < unidirectionalFlow[fwdOrBwd + "PacketLengthMin"]) {
            unidirectionalFlow[fwdOrBwd + "PacketLengthMin"] = avgPacketSize;
        }
    }


    
    unidirectionalFlow[fwdOrBwd + "Flow"].packets = packets;
    unidirectionalFlow[fwdOrBwd + "Flow"].bytes = bytes;
    flow.bytes = unidirectionalFlow[fwdOrBwd + "Flow"].bytes;
    flow.packets = unidirectionalFlow[fwdOrBwd + "Flow"].packets;

    


    await unidirectionalFlow.save();
    await flow.save();
}







// Update flow
app.put('/flow/:id', async (req, res) => {
    try {
        let flow = await Flow.findById(req.params.id);

        if (!flow) {
            console.log("Flow does not exist");
            // Orient by the UE pool, not by which direction happened to arrive
            // first. On a packet-in the first report is the real uplink, but when
            // records are recreated from existing switch rules (after a DB loss,
            // or a wipe while ONOS kept its rules) UpdateFlowStats walks
            // gtp_flows in arbitrary order. About half the flows then came back
            // inverted: the attack became the "backward" leg, the detector scored
            // the silent DN->UE reply instead, and the flag landed on
            // fwdFlow.srcIp - the DN - which would block its traffic to every UE.
            const [s, d, p] = req.params.id.split('-');
            if (!isUeAddress(s) && isUeAddress(d)) {
                await createNewFlow(`${d}-${s}-${p}`, "forward", 0, 0);
                flow = await Flow.findById(req.params.id);   // now exists, as "backward"
            } else {
                await createNewFlow(req.params.id, "forward", req.body.bytes, req.body.packets);
                return res.json("Flow created successfully");
            }
        }
        {
            let unidirectionalFlow = await UnidirectionalFlow.findById(flow.srcIp + "<->" + flow.dstIp + "<->" + flow.protocol);
            if (!unidirectionalFlow) {
                let unidirectionalFlow2 = await UnidirectionalFlow.findById(flow.dstIp + "<->" + flow.srcIp + "<->" + flow.protocol);
                await updateUnidirectionalFlow(flow, unidirectionalFlow2, req.body.bytes, req.body.packets);
                res.json("Flow updated successfully");
            }
            else {
                await updateUnidirectionalFlow(flow, unidirectionalFlow, req.body.bytes, req.body.packets);
                res.json("Flow updated successfully");
            }
            
            
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


//Get all flows
app.get('/flows', async (req, res) => {
    try{
        let flows = await Flow.find();
        await Promise.all(flows.map(async (flow) => {
            const currentTime = new Date();
            // Calculate the duration of the flow in seconds 
            let CreatedAtTime = new Date(flow.CreatedAt);
            flow.duration = (currentTime - CreatedAtTime) / 1000;
            //Calculate the duration in microseconds
            flow.durationInMicroseconds = (currentTime - CreatedAtTime) * 1000;
            await flow.save();
        }));
        res.json(flows);
    }
    catch(err){
        console.log(err);
    }
});

//Get all unidirectional flows
app.get('/unidirectionalFlows', async (req, res) => {
    try{
        let unidirectionalFlows = await UnidirectionalFlow.find();
        await Promise.all(unidirectionalFlows.map(async (unidirectionalFlow) => {
            const currentTime = new Date();
            // Calculate the duration of the flow in seconds 
            let CreatedAtTime = new Date(unidirectionalFlow.fwdFlow.CreatedAt);
            unidirectionalFlow.fwdFlow.duration = (currentTime - CreatedAtTime) / 1000;
            const currentDuration = unidirectionalFlow.fwdFlow.duration;
            unidirectionalFlow.bwdFlow.duration = (currentTime - CreatedAtTime) / 1000;

            //Calculate the duration in microseconds
            unidirectionalFlow.fwdFlow.durationInMicroseconds = (currentTime - CreatedAtTime) * 1000;
            unidirectionalFlow.bwdFlow.durationInMicroseconds = (currentTime - CreatedAtTime) * 1000;

            //Calculate the flow bytes per second
            unidirectionalFlow.flowBytesPerSecond = (unidirectionalFlow.fwdFlow.bytes + unidirectionalFlow.bwdFlow.bytes) / currentDuration;

            //Calculate the flow packets per second
            unidirectionalFlow.flowPacketsPerSecond = (unidirectionalFlow.fwdFlow.packets + unidirectionalFlow.bwdFlow.packets) / currentDuration;

            
            //Calculate the packets per second
            unidirectionalFlow.fwdPacketsPerSecond = unidirectionalFlow.fwdFlow.packets / currentDuration;
            unidirectionalFlow.bwdPacketsPerSecond = unidirectionalFlow.bwdFlow.packets / currentDuration;

            await unidirectionalFlow.save();
        }));
        res.json(unidirectionalFlows);
    }
    catch(err){
        console.log(err);
    }
});

//Delete all flows and unidirectional flows
app.delete('/deleteAll', async (req, res) => {
    try{
        await Flow.deleteMany();
        await UnidirectionalFlow.deleteMany();
        res.json("All flows and unidirectional flows deleted successfully");
    }
    catch(err){
        console.log(err);
    }
});


//Delete specific bidirectional flow
// Accepts either a unidirectional-flow ID ("a<->b<->p") or a bare IPv4 address,
// in which case every flow involving that address is removed.
//
// These used to be two routes, '/:id' and '/:ip'. Express matches the first
// registered route, so '/:ip' was unreachable: an IP was looked up as a flow ID,
// the null result was dereferenced, and the catch block never responded, so the
// client hung indefinitely. One handler, and every path now sends a response.
app.delete('/unidirectionalFlows/:id', async (req, res) => {
    try {
        const key = req.params.id;
        const unidirectionalFlow = await UnidirectionalFlow.findById(key);
        if (unidirectionalFlow) {
            await Flow.deleteMany({_id: unidirectionalFlow.fwdFlow._id});
            await Flow.deleteMany({_id: unidirectionalFlow.bwdFlow._id});
            await UnidirectionalFlow.deleteOne({_id: key});
            return res.json("Unidirectional flow deleted successfully");
        }
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(key)) {
            return res.status(404).json({ error: "Unidirectional flow not found" });
        }
        let removed = 0;
        const all = await UnidirectionalFlow.find();
        for (const u of all) {
            if (u.fwdFlow.srcIp === key || u.fwdFlow.dstIp === key) {
                await Flow.deleteMany({_id: u.fwdFlow._id});
                await Flow.deleteMany({_id: u.bwdFlow._id});
                await UnidirectionalFlow.deleteOne({_id: u._id});
                removed++;
            }
        }
        res.json({ message: "Unidirectional flows deleted successfully", removed });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


//Update Queue predictions 
app.put('/unidirectionalFlow/:id', async (req, res) => {
    try {
        let unidirectionalFlow = await UnidirectionalFlow.findById(req.params.id);
        if (!unidirectionalFlow) {
            res.status(404).json({ error: "Unidirectional flow not found" });
        } else {
            unidirectionalFlow.nbPredicitionQueue.shift();
            unidirectionalFlow.lrPredictionQueue.shift();

            unidirectionalFlow.nbPredicitionQueue.push(req.body.nbPrediction);
            unidirectionalFlow.lrPredictionQueue.push(req.body.lrPrediction);
            unidirectionalFlow.nbPredictionAvg = unidirectionalFlow.nbPredicitionQueue.reduce((a, b) => a + b, 0) / 5;
            unidirectionalFlow.lrPredictionAvg = unidirectionalFlow.lrPredictionQueue.reduce((a, b) => a + b, 0) / 5;
            // Only a UE can be auto-flagged. The drop rule matches the inner
            // source, so flagging a DN address would cut its downlink to every
            // UE. Manual POST /blocked-ip/<ip> still allows it deliberately.
            if (unidirectionalFlow.nbPredictionAvg === 1 && unidirectionalFlow.lrPredictionAvg === 1
                && !isUeAddress(unidirectionalFlow.fwdFlow.srcIp)) {
                console.warn(`refusing to auto-flag non-UE source ${unidirectionalFlow.fwdFlow.srcIp} (${unidirectionalFlow._id})`);
            } else if (unidirectionalFlow.nbPredictionAvg === 1  && unidirectionalFlow.lrPredictionAvg === 1) {
                //Add it to the flagged IP addresses
                let flaggedIp = await flaggedUEIP.findById(unidirectionalFlow.fwdFlow.srcIp);
                if(!flaggedIp){
                    const newFlaggedIp = new flaggedUEIP({
                        _id: unidirectionalFlow.fwdFlow.srcIp,
                        ueip: unidirectionalFlow.fwdFlow.srcIp
                    });
                    await newFlaggedIp.save();
                }
            }

            await unidirectionalFlow.save();
            res.json("Queue predictions updated successfully");
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



// POST endpoint to add a blocked IP address
app.post('/blocked-ip/:ip', async (req, res) => {
  try {
      const { ip } = req.params; // Get the IP address from the request parameters

      // Check if the IP is already in the blocked list
      const existingBlockedIp = await BlockedUEIP.findById(ip);
      if (existingBlockedIp) {
          return res.status(400).json({ message: 'IP address is already blocked' });
      }

      // If not, block the IP address
      const blockedIp = new BlockedUEIP({ _id: ip, ueip: ip });
      await blockedIp.save(); // Save the blocked IP address to the database
      res.json({ message: 'IP address blocked successfully' });
  } catch (error) {
      console.error('Error blocking IP address:', error);
      res.status(500).json({ message: 'Server error' });
  }
});


  //Get all blocked IP addresses
app.get('/blocked-ips', async (req, res) => {
    try {
      const blockedIps = await BlockedUEIP.find(); // Retrieve all blocked IP addresses from the database
      res.json(blockedIps); // Send the blocked IP addresses as a JSON response
    } catch (error) {
      console.error('Error getting blocked IP addresses:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });


//Check if an IP address is blocked
app.get('/blocked-ips/:ip', async (req, res) => {
    try {
      const { ip } = req.params; // Get the IP address from the request parameters
  
      const blockedIp = await BlockedUEIP.findById(ip); // Find the blocked IP address in the database
  
      if (blockedIp) {
        res.statusCode = 200;
      } else {
        res.statusCode = 404;
        res.json({ message: 'IP address is not blocked' });
      }
    } catch (error) {
      console.error('Error checking blocked IP address:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

//Delete a blocked IP address
app.delete('/blocked-ips/:ip', async (req, res) => {
    try {
      const { ip } = req.params; // Get the IP address from the request parameters
  
      await BlockedUEIP.findByIdAndDelete(ip); // Delete the blocked IP address from the database
  
      res.json({ message: 'IP address unblocked successfully' });
    } catch (error) {
      console.error('Error unblocking IP address:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  //Delete all blocked IP addresses
app.delete('/blocked-ips', async (req, res) => {
    try {
      await BlockedUEIP.deleteMany(); // Delete all blocked IP addresses from the database
      res.json({ message: 'All IP addresses unblocked successfully' });
    } catch (error) {
      console.error('Error unblocking IP addresses:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });



  //Find all the flows which average Queue is 1 
app.get('/flaggedIps', async (req, res) => {
    try {
      const flaggedIps = await flaggedUEIP.find(); // Retrieve all flagged IP addresses from the database
      res.json(flaggedIps); // Send the flagged IP addresses as a JSON response
    } catch (error) {
      console.error('Error getting flagged IP addresses:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  //Get the top 1 flagged IP address
app.get('/flaggedIps/top', async (req, res) => {
    try {
      const flaggedIps = await flaggedUEIP.find(); // Retrieve all flagged IP addresses from the database
      res.json(flaggedIps[0]); // Send the flagged IP addresses as a JSON response
    } catch (error) {
      console.error('Error getting flagged IP addresses:', error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  //Delete a flagged IP address
  app.delete('/flagged-ips/:ip', async (req, res) => {
    try {
      const { ip } = req.params; // Get the IP address from the request parameters
  
      await flaggedUEIP.findByIdAndDelete(ip); // Delete the flagged IP address from the database
  
      res.json({ message: 'IP address unflagged successfully' });
    } catch (error) {
      console.error('Error unflagging IP address:', error);
      res.status(500).json({ message: 'Server error' });
    }
  }
);




//Clean all dbs
app.delete('/clean', async (req, res) => {
    try {
        await Flow.deleteMany();
        await UnidirectionalFlow.deleteMany();
        await BlockedUEIP.deleteMany();
        await flaggedUEIP.deleteMany();
        res.json("All databases cleaned successfully");
    } catch (error) {
        console.error('Error cleaning databases:', error);
        res.status(500).json({ message: 'Server error' });
    }
}
);




  







app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});













