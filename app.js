/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

var userState = {"john": {
    stateName:"menu",
    clarify:"false"
}};

//var userList = { users: [{id:"john", state:"Directions"}, {id:"jane", state:"Directions"}]};

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function(messageID) {
            console.log("Received delivery confirmation for message ID: %s",
                messageID);
        });
    }

    console.log("All message before %d were delivered.", watermark);
}

/*
 * Get the state of the given user
 */
function getUser(id) {
    return userState[id];
}

function makeUser(id) {
    userState[id] = {
        stateName:"menu",
        clarify:"false"
    };
}

/*
 * Set the state of the given user
 */
function setUserState(id, newState) {
    userState[id].stateName = newState;
}

function setUserDirectClarify(id, newClarify) {
    userState[id].clarify = newClarify;
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
    var sender = senderID.toString().toLowerCase();
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

    if (getUser(senderID) === undefined) {
        makeUser(senderID);

        console.log("undefined found. new state is " + getUser(senderID).stateName +
            " with clarification " + getUser(senderID).clarify);
    }

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

    /*
  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;
  */

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (quickReply) {
      var quickReplyPayload = quickReply.payload;
      // If there was a conflict in the directions, a clarification was requested.
      if (getUser(senderID).clarify === true) {
          console.log("Clarification requested. The user's clarification is set to " + getUser(senderID).clarify);
          setUserDirectClarify(senderID, false);
          // In future updates, this text message would be replaced with a call to the URL-sending code.
          sendTextMessage(senderID, quickReplyPayload);
      }
      // Otherwise, this is our state-changing code from the main menu.
       else {
          setUserState(senderID, quickReplyPayload);

          switch (quickReplyPayload) {
              case "directions":
                  sendTextMessage(senderID, "You are in Directions. Enter a location to go, or exit using the keyword \"exit\".");
                  break;
              case "fun facts":
                  setUserState(senderID, "menu");
                  sendFunFact(senderID);
                  break;
              case "explore":
                  setUserState(senderID, "menu");
                  sendExplore(senderID);
                  break;
              default:
                  sendTextMessage(senderID, "wut did you do. state is " + quickReplyPayload);
          }
      }
    return;
  }

  else if (messageText) {
      messageText = messageText.toLowerCase();
      if (messageText === "menu" || messageText === "go back" || messageText === "back" || messageText === "exit" || messageText === "quit" || messageText === "escape") {
          setUserState(senderID, "menu");
          sendMenu(senderID);
      } else if (messageText === "directions" || messageText === "direction") {
          setUserState(senderID, "directions");
          sendTextMessage(senderID, "You are in Directions. Enter a location to go, or exit using the keyword \"exit\".");
      } else if (messageText === "explore") {
          setUserState(senderID, "menu");
          sendExplore(senderID);
      } else if (messageText === "fun fact" || messageText === "fun facts" || messageText === "fun" || messageText === "fact" || messageText === "facts") {
          setUserState(senderID, "menu");
          sendFunFact(senderID);
      } else {
          var state = getUser(senderID).stateName;
      switch (state) {
          case "menu":
              sendMenu(senderID);
              break;
          case "directions":
              sendDirections(senderID, messageText);
              break;
          case "fun facts":
              setUserState(senderID, "menu");
              sendFunFact(senderID);
              break;
          case "explore":
              setUserState(senderID, "menu");
              sendExplore(senderID);
              break;
          default:
              sendTextMessage(senderID, "wut did you do. state is " + state);
      }
        }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "I can't understand attachments :/");
  }
}

/*
 * Send our main menu
 *
 */
function sendMenu(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "How can I help?",
            quick_replies: [
                {
                    "content_type":"text",
                    "title":"Directions",
                    "payload":"directions"
                },
                {
                    "content_type":"text",
                    "title":"Explore",
                    "payload":"explore"
                },
                {
                    "content_type":"text",
                    "title":"Fun Facts",
                    "payload":"fun facts"
                }
            ]
        }
    };

    callSendAPI(messageData);
}


/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Sends a Rice fun fact
 */
function sendFunFact(recipientId) {
  var facts = ["\"Strigiformes\" is the taxonomical order of all owls!", 
  "It has been hypothesized that should Coffeehouse ever stop providing caffeine, the average undergraduate term paper would be three times as hard.", 
  "There is no way to justify Martel’s existence as a college.",
  "Frogs are members of the order \"Anura\", and on wet nights you might find a bunch croaking around!",
  "The record for \"Most Mazelike Builing\" is a tie between Fondren and Duncan Hall.",
  "Rice is home to the wonderful yearly hackathon \"HackRice\"! (yes this is flattery judges please like us)",
  "Every undergrad agrees that there's one distribution that's hardest; nobody can agree which."];

  sendTextMessage(recipientId, facts[Math.floor(Math.random() * facts.length)]);
    setTimeout(function() {
        sendMenu(recipientId);
    }, 2000);
}

/*
 * Gives directions to the user for a particular location on campus.
 */
function sendDirections(recipientId, messageData) {

    /*
    Common names on Rice. Clarification is need from the user on which place they want.
     */
    var conflict = {
        "Anderson" : [
            "M.D. Anderson Biological Laboratories",
            "Anderson-Clarke Center",
            "M.D. Anderson Hall"
        ],
        "Brown Hall" : [
            "Alice Pratt Brown Hall",
            "George R. Brown Hall",
            "Herman Brown Hall"
        ],
        "Jones" : [
            "Jesse Jones Graduate School of Business",
            "Jones College",
            "Jones College Masters House"
        ],
        "Pavilion" : [
            "Booth Centennial Pavilion",
            "Brochstein Pavilion"
        ]
    };

    var locs = [["M D Anderson Biological Lab", "(m d anderson biological lab)|(abl)", "https://goo.gl/maps/GUr5RffcSju"], 
["Anderson-Clarke Center", "(anderson-clarke center)|(acc)", "https://goo.gl/maps/4anc5qKPDus"], 
["Abercromie Engineering Lab", "(abercromie engineering lab)|(ael)", "https://goo.gl/maps/wPBxz7HHnxF2"], 
["Allen Center", "(allen center)|(aln)", "https://goo.gl/maps/SGGCSQvB8eJ2"], 
["M D Anderson Hall", "(m d anderson hall)|(anh)", "https://goo.gl/maps/KYpf6JNxeSr"], 
["Alice Pratt Brown Hall", "(alice pratt brown hall)|(apb)", "https://goo.gl/maps/toGFGJqMhin"], 
["Baker College", "(baker college)|(bkc)", "https://goo.gl/maps/W5NJNnAFW2q"], 
["James Baker Hall", "(james baker hall)|(bkh)", "https://goo.gl/maps/s5c2Ww5cTsS2"], 
["Margaret Root Brown College", "(margaret root brown college)|(bnc)", "https://goo.gl/maps/wvXbrkh3vgp"], 
["Brochstein Pavilion", "(brochstein pavilion)|(bpv)", "https://goo.gl/maps/9wZWZCeSAsJ2"], 
["BioScience Research Collab", "(bioscience research collab)|(brc)", "https://goo.gl/maps/54Md9RPF5L42"], 
["Brockman Hall for Physics", "(brockman hall for physics)|(brk)", "https://goo.gl/maps/njYn4m7rakt"], 
["Cohen House", "(cohen house)|(coh)", "https://goo.gl/maps/MroVJ9tfG522"], 
["Dell Butcher Hall", "(dell butcher hall)|(dbh)", "https://goo.gl/maps/M2U7GS7v98v"], 
["Duncan College", "(duncan college)|(dcc)", "https://goo.gl/maps/U5w8gZ9gWFD2"], 
["Anne and Charles Duncan Hall", "(anne and charles duncan hall)|(dch)", "https://goo.gl/maps/Bi1oX3jU9ak"], 
["Facilities Engr Planning Bldg", "(facilities engr planning bldg)|(fep)", "https://goo.gl/maps/48giEEQKHr52"], 
["Fondren Library", "(fondren library)|(fon)", "https://goo.gl/maps/rjZhEt4DPmH2"], 
["Greenbriar Building", "(greenbriar building)|(gbb)", "https://goo.gl/maps/S4q88t38iX72"], 
["Greenhouse", "(greenhouse)|(ghs)", "https://goo.gl/maps/cMVgGo6CC4J2"], 
["George R Brown Hall", "(george r brown hall)|(grb)", "https://goo.gl/maps/oMB2ztggJmk"], 
["Gibbs Rec and Wellness Center", "(gibbs rec and wellness center)|(grw)", "https://goo.gl/maps/WXVQGEqEwJF2"], 
["Hamman Hall", "(hamman hall)|(ham)", "https://goo.gl/maps/VqmcP2hFpDn"], 
["Herman Brown Hall for Math Sci", "(herman brown hall for math sci)|(hbh)", "https://goo.gl/maps/xc1Edcf4rsy"], 
["Holloway Field and Ley Track", "(holloway field and ley track)|(hfd)", "https://goo.gl/maps/6fdEGhsb8PA2"], 
["Harry C Hanszen College", "(harry c hanszen college)|(hnz)", "https://goo.gl/maps/Ko15SBHpRfP2"], 
["Robert R Herring Hall", "(robert r herring hall)|(hrg)", "https://goo.gl/maps/7vsFvrLtkco"], 
["Herzstein Hall", "(herzstein hall)|(hrz)", "https://goo.gl/maps/NgTG6Qoou722"], 
["Huff House", "(huff house)|(huf)", "https://goo.gl/maps/FM8Q9CVtkuy"], 
["Humanities Building", "(humanities building)|(hum)", "https://goo.gl/maps/XKesMenuPar"], 
["Jones College", "(jones college)|(joc)", "https://goo.gl/maps/X51ckCbXZx12"], 
["Howard Keck Hall", "(howard keck hall)|(kck)", "https://goo.gl/maps/LhoKRLHxLdD2"], 
["Keith-Weiss Geological Lab", "(keith-weiss geological lab)|(kwg)", "https://goo.gl/maps/Gd53FZmieNk"], 
["Ley Student Center", "(ley student center)|(ley)", "https://goo.gl/maps/RjSgNEXuawr"], 
["Lovett College", "(lovett college)|(lvc)", "https://goo.gl/maps/38bZfTnfjZ52"], 
["Lovett Hall", "(lovett hall)|(lvh)", "https://goo.gl/maps/vdcciUGYHRx"], 
["McMurtry College", "(mcmurtry college)|(mcm)", "https://goo.gl/maps/bUfj3r4ooAm"], 
["Janice and Robert McNair Hall", "(janice and robert mcnair hall)|(mcn)", "https://goo.gl/maps/xbvGSC2u9gq"], 
["Martel Center for Cont Studies", "(martel center for cont studies)|(mcs)", "https://goo.gl/maps/J1hnhYiVydJ2"], 
["Mechanical Engineering Bldg", "(mechanical engineering bldg)|(meb)", "https://goo.gl/maps/W68jhRG9Zn42"], 
["Media Center", "(media center)|(med)", "https://goo.gl/maps/bd97WVyMQpo"], 
["Mechanical Laboratory", "(mechanical laboratory)|(mel)", "https://goo.gl/maps/XCwQtshnjgs"], 
["Martel College", "(martel college)|(mlc)", "https://goo.gl/maps/49K7eNMqhBF2"], 
["S G Mudd Computer Science Lab", "(s g mudd computer science lab)|(mud)", "https://goo.gl/maps/Qm9bLsEgUv52"], 
["North Servery", "(north servery)|(nsv)", "https://goo.gl/maps/5agW4LkomU22"], 
["Oshman Engineer Design Kichen", "(oshman engineer design kichen)|(oed)", "https://goo.gl/maps/D93h8MtvXey"], 
["Police Department", "(police department)|(pol)", "https://goo.gl/maps/5kKwi9gp53S2"], 
["Rice Children's Campus", "(rice children's campus)|(rcc)", "https://goo.gl/maps/kUGpmokVrEx"], 
["Reckling Park at Cameron Field", "(reckling park at cameron field)|(rck)", "https://goo.gl/maps/WsMJsD41aN82"], 
["Rice Graduate Apartments", "(rice graduate apartments)|(rga)", "https://goo.gl/maps/j6jAEtDUQ7T2"], 
["Rice Health and Wellness Cntr", "(rice health and wellness cntr)|(rhw)", "https://goo.gl/maps/gzJuEixXTZu"], 
["Rice Memorial Center", "(rice memorial center)|(rmc)", "https://goo.gl/maps/EuipxLCTrdp"], 
["Rice Village Apartments", "(rice village apartments)|(rva)", "https://goo.gl/maps/i5Md9yZNEPn"], 
["Ryon Engineering Laboratory", "(ryon engineering laboratory)|(ryn)", "https://goo.gl/maps/oQD8unXVkJo"], 
["Rayzor Hall", "(rayzor hall)|(rzr)", "https://goo.gl/maps/DCvjNkpCE872"], 
["Sewall Hall", "(sewall hall)|(sew)", "https://goo.gl/maps/zaHsCqqwe6p"], 
["South Plant", "(south plant)|(spl)", "https://goo.gl/maps/dYqLh2DdN7J2"], 
["Sid Richardson College", "(sid richardson college)|(src)", "https://goo.gl/maps/YP5bYXohTCP2"], 
["Space Science and Tech Bldg", "(space science and tech bldg)|(sst)", "https://goo.gl/maps/SJWfraBFJV42"], 
["South Servery", "(south servery)|(ssv)", "https://goo.gl/maps/BGGmY981uMx"], 
["Rice Stadium", "(rice stadium)|(sta)", "https://goo.gl/maps/U2DX4dsA22n/"], 
["To Be Announced", "(to be announced)|(tba)", "SPECIAL CASE - EXPLAIN"], 
["Tudor Fieldhouse", "(tudor fieldhouse)|(tud)", "https://goo.gl/maps/JfsuZKArcHr"], 
["Wiess President's House", "(wiess president's house)|(wph)", "https://goo.gl/maps/wfZqjZVPChs"], 
["Will Rice College", "(will rice college)|(wrc)", "https://goo.gl/maps/AypESjPaey22"], 
["Harry C Weiss College", "(harry c weiss college)|(wsc)", "https://goo.gl/maps/97Rx2gFEEbP2"], 
["West Servery", "(west servery)|(wsv)", "https://goo.gl/maps/6kUsgQyi3h12"], 
];

    /*
     Regex expressions for all the various places on campus.
      See http://www.rice.edu/maps/Rice-University-Color-Campus-Map.pdf for a list of the major spots on campus.
      */

      /*
    var locs = [
        ["Abercrombie Engineering Laboratory", "abercrombie\\s(engineering\\slaboratory)*"],
        ["Allen Business Center", "allen\\s(business\\s)*center"],
        ["conflict:Anderson", "anderson"],
        ["M.D. Anderson Biological Laboratories", "(m\\.*d\\.*\\s)*anderson\\s(biological\\s)*lab((oratories)|(oratory))*"],
        ["Anderson-Clarke Center", "anderson((-|\\s)+clarke)*\\scenter"],
        ["M.D. Anderson Hall", "(m\\.*d\\.*\\s)*anderson\\shall"],
        ["Baker College", "baker(\\scollege)*"],
        ["Baker College Masters House", "baker(\\scollege)*(\\smaster)+.*(house)*"],
        ["James A. Baker Hall", "(james\\s(a\\.*\\s)*)*baker\\shall"],
        ["BioScience Research Collaborative", "bioscience(\\sresearch)*(\\scollaborative)*"],
        ["conflict: Pavilion", "pavilion"],
        ["Booth Centennial Pavilion", "(booth\\s)*centennial\\spavilion"],
        ["Brochstein Pavilion", "brochstein(\\spavilion)*"],
        ["Brockman Hall for Physics", "brockman(\\shall)*(\\sfor\\sphysics)*"],
        ["Brown College", "brown(\\scollege)*"],
        ["Brown College Masters House", "brown(\\scollege)*(\\smaster)+.*(house)*"],
        ["conflict:Brown Hall", "brown\\shall"],
        ["Alice Pratt Brown Hall", "(((alice\\s)*(pratt\\s)+)|((alice\\s)+(pratt\\s)*))brown\\shall"],
        ["George R. Brown Hall", "(((george\\s)*(r\\.*\\s)+)|((george\\s)+(r\\.*\\s)*))brown\\shall"],
        ["Herman Brown Hall", "herman\\sbrown\\shall"],
        ["Dell Butcher Hall", "((dell\\s)+(butcher\\s)*)|((dell\\s)*(butcher\\s)+)hall"],
        ["Cohen House", "cohen(\\shouse)*"],
        ["John L. Cox Fitness Center", "(john\\s)*(l(\\.)*\\s)*(cox\\s)*fitness\\scenter"],
        ["conflict:Duncan", "duncan"],
        ["Duncan College", "duncan\\scollege"],
        ["Duncan College Masters House", "duncan\\s(college\\s)*master.*house"],
        ["Duncan Hall", "duncan\\shall"],
        ["Facilities Engineering and Planning Building", "facilities\\s(engineering and planning\\s)*building"],
        ["Fondren Library", "((fondren\\s)*(library)+)|((fondren)+\\s*(library)*)"],
        ["George R. Brown School of Engineering", "(george\\s(r\\.*\\s)*brown)+|(school\\sof\\sengineering)+"],
        ["Gibbs Recreation and Wellness Center", "((gibbs\\s)*rec(reation)*\\s(and\\swellness\\s)*center)|(gym)"],
        ["Susanne M. Glasscock School of Continuing Studies", "(susanne\\sm\\.*\\s)*(glasscock\\s)*school\\sof\\scontinuing\\sstudies"],
        ["Greenbriar Building", "greenbriar(\\sbuilding)*"],
        ["Greenhouse", "greenhouse"],
        ["Hamman Hall", "hamman\\shall"],
        ["Hanszen College", "hanszen(\\scollege)*"],
        ["Hanszen College Masters House", "hanszen(\\scollege)*(\\smaster)+.*(house)*"],
        ["Robert R. Herring Hall", "(robert\\sr\.*\\s)*herring\\shall"],
        ["Herzstein Hall", "herzstein\\shall"],
        ["Holloway Field", "holloway(\\sfield)*"],
        ["Housing and Dining", "housing\\sand\\sdining"],
        ["Huff House", "huff\\shouse"],
        ["Humanities Building", "humanities\\sbuilding"],
        ["School of Humanities", "school\\sof\\shumanities"],
        ["conflict:Jones", "jones"],
        ["Jesse Jones Graduate School of Business", "(jesse\\s)*jones\\s(graduate\\s)*school(\\sof)*(\\sbusiness)+"],
        ["Jones College", "jones\\scollege"],
        ["Jones College Masters House", "jones(\\scollege)*(\\smaster)+.*(house)*"],
        ["Keck Hall", "kec\\shall"],
        ["Keith-Wiess Geological Laboratories", "keith-*\\s*wiess\\s*(geological\\slaborator(ies)|y)*"]
    ];*/

    // Search for regexes
    var matches = [];
    locs.forEach(function (location) {
        var reg = new RegExp(location[1]);
        if (reg.test(messageData) === true) {
            matches.push([location[0], location[2]]);
        }
    });

    /*
     Get the highest result, and an error otherwise. The regexes are in increasing complexity
     i.e. the brown conflict regex is searched before brown hall. This means brown conflict will be pushed,
     but so will brown hall, and since brown hall was pushed more recently, we know the user meant brown hall
     and not some generic brown.
     */
    var lastLoc = matches.length === 0 ? "Location not found." : matches[matches.length-1];

    console.log("Finished the matching: " + lastLoc);

    // Check if it is a conflict
     if (lastLoc.substr(0,9) == "conflict:") {
        // Execute the conflictMenu
        setUserDirectClarify(recipientId, true);
        console.log("clarification is " + getUser(recipientId).clarify);
        sendConflictMenu(recipientId, conflict[lastLoc.substr(9, lastLoc.length)]);
    } else {
        sendTextMessage(recipientId, lastLoc[0] +" is located at " + lastLoc[1]);
    }
}

/*
Helper function that takes in a list of possible conflict locations and sends them to the user.
 */
function sendConflictMenu(recipientId, conflictLists) {

    console.log("Checking conflicts for " + conflictLists.toString());

    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Did you mean:",
            
            quick_replies: conflictLists.map(function (option) {
                return {
                    "content_type":"text",
                    // Titles are limited to 20 characters.
                    "title":option.substr(0, 20),
                    "payload":option
                };
            })

        }
    };

    callSendAPI(messageData);
}

/*
 * Sends the user to a location to explore
 */
function sendExplore(recipientId) {
    var locations = ["The Frog Wall is a wall that sounds just like a frog chirping if you lick your thumb and run it down the wall.",
        "Rice has a piece of the historic Berlin wall on campus that divided Germany from 1961 to 1989.",
        "Duncan Hall, Rice's Computational Engineering Building, has an incredible ceiling inspired by many world cultures.",
        "Skyspace is an art installation by James Turrell. It lights up different colors at night, and performances are held within it."];

    var images = ["http://content-img.newsinc.com/jpg/374/29570937/24703533.jpg?t=1439989620",
        "http://mw2.google.com/mw-panoramio/photos/medium/66655372.jpg",
        "http://timeline.centennial.rice.edu/site_media/uploads/images/2011-03-24/Duncan_Hall_interior_copy_tif_800x700_q85.jpg",
        "http://skyspace.rice.edu/site_media/media/cache/fb/6b/fb6b16ad6fc3576b29168317daacf4e2.png"];

    var links = ["https://goo.gl/maps/SpC9zE29evM2",
        "https://goo.gl/maps/3pzPxMp9yYC2",
        "https://goo.gl/maps/M1VsyKEDrwq",
        "https://goo.gl/maps/hrhCZW94hWt"];

    var rand = Math.floor(Math.random() * locations.length);

    var imageMessage = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: images[rand]
                }
            }
        }
    };

    callSendAPI(imageMessage);
    sendTextMessage(recipientId, locations[rand] + " Here's a Google Maps link: " + links[rand]);
    setTimeout(function() {
        sendMenu(recipientId);
    }, 2000);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}



/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

