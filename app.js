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
    clarify:"false",
    funFact:[],
    explore:[]
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

function contains(a, obj) {
    var i = a.length;
    while (i--) {
        if (a[i] === obj) {
            return true;
        }
    }
    return false;
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
        clarify:"false",
        funFact:[],
        explore:[]
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

    // var fs = require('fs');
    // fs.writeFile("feedback.xt", "Hey there!", function(err) {
    //     if(err) {
    //         return console.log(err);
    //     }
    //
    //     console.log("The file was saved!");
    // });

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
              case "businesses":
                  setUserState(senderID, "businesses");
                  sendTextMessage(senderID, "You're in Businesses/Serveries. Enter a business, servery, or service, or exit by using \"exit\".");
                  break;
              case "explore":
                  setUserState(senderID, "menu");
                  sendExplore(senderID);
                  break;
              case "about":
                  setUserState(senderID, "menu");
                  sendAbout(senderID);
                  sendMenu(senderID);
                  break;
              case "help":
                  setUserState(senderID, "menu");
                  sendHelp(senderID);
                  sendMenu(senderID);
                  break;
              case "feedback":
                  setUserState(senderID, "menu");
                  sendFeedback(senderID);
                  sendMenu(senderID);
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
      } else if(messageText === "businesses" || messageText == "business" || messageText == "servery" || messageText == "serveries") {
          setUserState(senderID, "businesses");
          sendTextMessage(senderID, "You're in Businesses/Serveries. Enter a business, servery, or service, or exit using the keyword \"exit\".");
      } else if (messageText === "fun fact" || messageText === "fun facts" || messageText === "fun" || messageText === "fact" || messageText === "facts") {
          setUserState(senderID, "menu");
          sendFunFact(senderID);
          sendMenu(senderID);
      } else if (messageText === "upupdowndownleftrightleftrightbastart" || messageText === "konami" || messageText === "konami code" || messageText === "up up down down left right left right b a start") {
          setUserState(senderID, "menu");
          sendEasterEgg(senderID);
          sendMenu(senderID);
      } else if (messageText === "about" || messageText === "more") {
          setUserState(senderID, "menu");
          sendAbout(senderID);
          sendMenu(senderID);
      } else if (messageText === "help") {
          setUserState(senderID, "menu");
          sendHelp(senderID);
          sendMenu(senderID);
      } else if (messageText == "feedback" || messageText == "error" || messageText == "errors" || messagetext == "bug"){
          setUserState(senderID, "menu");
          sendFeedback(senderID);
          sendMenu(senderID);
      } else {
          var state = getUser(senderID).stateName;
      switch (state) {
          case "menu":
              sendMenu(senderID);
              break;
          case "directions":
              sendDirections(senderID, messageText);
              break;
          case "businesses":
              sendBusiness(senderID, messageText);
              break;
          case "fun facts":
              setUserState(senderID, "menu");
              sendFunFact(senderID);
              break;
          case "explore":
              setUserState(senderID, "menu");
              sendExplore(senderID);
              break;
          case "about":
              setUserState(senderID, "menu");
              sendAbout(senderID);
              break;
          case "help":
              setUserState(senderID, "menu");
              sendHelp(senderID);
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
                    "title":"Business/Servery",
                    "payload":"businesses"
                },
                {
                    "content_type":"text",
                    "title":"Fun Facts",
                    "payload":"fun facts"
                },
                {
                    "content_type":"text",
                    "title":"About",
                    "payload":"about"
                },
                {
                    "content_type":"text",
                    "title":"Help",
                    "payload":"help"
                }
            ]
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
        "Every student insists that their residential college is the best. McMurtry is obviously superior, but that might just be my developers' bias. :)",
        "Frogs are members of the order \"Anura\", and after Houston rains, you might find a bunch croaking around!",
        "The record for \"Most Maze-like Building\" is a tie between Fondren and Duncan Hall.",
        "Rice is home to the wonderful yearly hackathon \"HackRice\"! I was made there!",
        "Every undergrad agrees that there's one distribution that's hardest; nobody can agree which (humanities, social sciences, or math and science).",
        "Baker 13 is not a myth.",
        "A Rice saying goes, \"There's a tree for every student, and two squirrels for every tree!\" (Careful though, the squirrels bite.)"];

    var rand = Math.floor(Math.random() * facts.length);

    //if we need to refresh array (all have been given)
    var arr = userState[recipientId].funFact;
    if (arr.length >= facts.length) {
        userState[recipientId].funFact = [];
        arr = [];
    }

    //while chosen fun fact has already been given
    while (contains(arr, rand)) {
        rand = Math.floor(Math.random() * facts.length);
    }

    sendTextMessage(recipientId, facts[rand]);

    //mark that fun fact was given
    userState[recipientId].funFact.push(rand);

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
            ["M.D. Anderson Biological Laboratories", "https://goo.gl/maps/GUr5RffcSju"],
            ["Anderson-Clarke Center", "https://goo.gl/maps/4anc5qKPDus"],
            ["M.D. Anderson Hall" , "https://goo.gl/maps/KYpf6JNxeSr"],
        ],
        "Brown Hall" : [
            ["Alice Pratt Brown Hall", "https://goo.gl/maps/toGFGJqMhin"],
            ["George R. Brown Hall", "https://goo.gl/maps/oMB2ztggJmk"],
            ["Herman Brown Hall", "https://goo.gl/maps/xc1Edcf4rsy"]
        ],
        "Jones" : [
            ["Jesse Jones Graduate School of Business", "https://goo.gl/maps/X51ckCbXZx12"],
            ["Jones College", "https://goo.gl/maps/X51ckCbXZx12"],
            ["Jones College Masters House", "https://goo.gl/maps/X51ckCbXZx12"]
        ],
        "Pavilion" : [
            ["Booth Centennial Pavilion", "https://goo.gl/maps/9wZWZCeSAsJ2"],
            ["Brochstein Pavilion", "https://goo.gl/maps/9wZWZCeSAsJ2"]
        ]
    };


    //add master's houses
    /*
     Regex expressions for all the various places on campus.
     See http://www.rice.edu/maps/Rice-University-Color-Campus-Map.pdf for a list of the major spots on campus.
     */
    var locs = [
["conflict:Anderson", "anderson"],
["M.D. Anderson Biological Laboratories", "(m d anderson biological lab)|(abl)|((m\\.*d\\.*\\s)*anderson\\s(biological\\s)*lab((oratories)|(oratory))*)", "https://goo.gl/maps/GUr5RffcSju"],
["Anderson-Clarke Center", "(anderson-clarke center)|(acc)|(anderson((-|\\s)+clarke)*\\scenter)", "https://goo.gl/maps/4anc5qKPDus"],
["M.D. Anderson Hall", "(m d anderson hall)|(anh)|((m\\.*d\\.*\\s)*anderson\\shall)", "https://goo.gl/maps/KYpf6JNxeSr"],
["Abercromie Engineering Lab", "(abercromie engineering lab)|(ael)|(abercrombie\\s(engineering\\slaboratory)*)", "https://goo.gl/maps/wPBxz7HHnxF2"],
["Allen Center", "(allen center)|(aln)|(allen\\s(business\\s)*center)", "https://goo.gl/maps/SGGCSQvB8eJ2"],
["Margaret Root Brown College", "(margaret root brown college)|(bnc)|(brown(\\scollege)*)", "https://goo.gl/maps/wvXbrkh3vgp"],
["conflict:Brown Hall", "brown\\shall"],
["Alice Pratt Brown Hall", "(alice pratt brown hall)|(apb)|((((alice\\s)*(pratt\\s)+)|((alice\\s)+(pratt\\s)*))brown\\shall)", "https://goo.gl/maps/toGFGJqMhin"],
["George R. Brown Hall", "(george r brown hall)|(grb)|((((george\\s)*(r\\.*\\s)+)|((george\\s)+(r\\.*\\s)*))brown\\shall)", "https://goo.gl/maps/oMB2ztggJmk"],
["Herman Brown Hall for Math Sci", "(herman brown hall for math sci)|(hbh)|(herman\\sbrown\\shall)", "https://goo.gl/maps/xc1Edcf4rsy"],
["Baker College", "(baker college)|(bkc)|(baker(\\scollege)*)", "https://goo.gl/maps/W5NJNnAFW2q"],
["James Baker Hall", "(james baker hall)|(bkh)|((james\\s(a\\.*\\s)*)*baker\\shall)", "https://goo.gl/maps/s5c2Ww5cTsS2"],
["conflict:Pavilion", "pavilion"],
["Booth Centennial Pavilion", "(booth\\s)*centennial\\spavilion", "https://goo.gl/maps/9wZWZCeSAsJ2"],
["Brochstein Pavilion", "(brochstein pavilion)|(bpv)|(brochstein(\\spavilion)*)", "https://goo.gl/maps/9wZWZCeSAsJ2"],
["BioScience Research Collab", "(bioscience research collab)|(brc)|(bioscience(\\sresearch)*(\\scollaborative)*)", "https://goo.gl/maps/54Md9RPF5L42"],
["Brockman Hall for Physics", "(brockman hall for physics)|(brk)|(brockman(\\shall)*(\\sfor\\sphysics)*)", "https://goo.gl/maps/njYn4m7rakt"],
["Cohen House", "(cohen house)|(coh)|(cohen(\\shouse)*)", "https://goo.gl/maps/MroVJ9tfG522"],
["Dell Butcher Hall", "(dell butcher hall)|(dbh)|(((dell\\s)+(butcher\\s)*)|((dell\\s)*(butcher\\s)+)hall)", "https://goo.gl/maps/M2U7GS7v98v"],
["Duncan College", "(duncan college)|(dcc)|(duncan\\scollege)", "https://goo.gl/maps/U5w8gZ9gWFD2"],
["Anne and Charles Duncan Hall", "(anne and charles duncan hall)|(dch)|(duncan\\shall)", "https://goo.gl/maps/Bi1oX3jU9ak"],
["Facilities Engr Planning Bldg", "(facilities engr planning bldg)|(fep)|(facilities\\s(engineering and planning\\s)*building)", "https://goo.gl/maps/48giEEQKHr52"],
["Fondren Library", "(fondren library)|(fon)|(((fondren\\s)*(library)+)|((fondren)+\\s*(library)*))", "https://goo.gl/maps/rjZhEt4DPmH2"],
["Greenbriar Building", "(greenbriar building)|(gbb)|(greenbriar(\\sbuilding)*)", "https://goo.gl/maps/S4q88t38iX72"],
["Greenhouse", "(greenhouse)|(ghs)|(greenhouse)", "https://goo.gl/maps/cMVgGo6CC4J2"],
["Gibbs Rec and Wellness Center", "(gibbs rec and wellness center)|(grw)|(((gibbs\\s)*rec(reation)*\\s(and\\swellness\\s)*center)|(gym))", "https://goo.gl/maps/WXVQGEqEwJF2"],
["Hamman Hall", "(hamman hall)|(ham)|(hamman\\shall)", "https://goo.gl/maps/VqmcP2hFpDn"],
["Holloway Field and Ley Track", "(holloway field and ley track)|(hfd)|(holloway(\\sfield)*)", "https://goo.gl/maps/6fdEGhsb8PA2"],
["Harry C Hanszen College", "(harry c hanszen college)|(hnz)|(hanszen(\\scollege)*)", "https://goo.gl/maps/Ko15SBHpRfP2"],
["Robert R Herring Hall", "(robert r herring hall)|(hrg)|((robert\\sr\.*\\s)*herring\\shall)", "https://goo.gl/maps/7vsFvrLtkco"],
["Herzstein Hall", "(herzstein hall)|(hrz)", "https://goo.gl/maps/NgTG6Qoou722"], 
["Huff House", "(huff house)|(huf)", "https://goo.gl/maps/FM8Q9CVtkuy"], 
["Humanities Building", "(humanities building)|(hum)", "https://goo.gl/maps/XKesMenuPar"],
["conflict:Jones", "jones"],
["Jesse Jones Graduate School of Business", "(jesse\\s)*jones\\s(graduate\\s)*school(\\sof)*(\\sbusiness)+", "https://goo.gl/maps/X51ckCbXZx12"],
["Jones College", "(jones college)|(joc)|(jones)", "https://goo.gl/maps/X51ckCbXZx12"],
["Jones College Masters House", "jones(\\scollege)*(\\smaster)+.*(house)*", "https://goo.gl/maps/X51ckCbXZx12"],
["Howard Keck Hall", "(howard keck hall)|(kck)|(kec\\shall)", "https://goo.gl/maps/LhoKRLHxLdD2"],
["Keith-Weiss Geological Lab", "(keith-weiss geological lab)|(kwg)|(keith-*\\s*wiess\\s*(geological\\slaborator(ies)|y)*)", "https://goo.gl/maps/Gd53FZmieNk"],
["Ley Student Center", "(ley student center)|(ley)", "https://goo.gl/maps/RjSgNEXuawr"], 
["Lovett College", "(lovett college)|(lovett)|(lvc)", "https://goo.gl/maps/38bZfTnfjZ52"],
["Lovett Hall", "(lovett hall)|(lvh)", "https://goo.gl/maps/vdcciUGYHRx"], 
["McMurtry College", "(mcmurtry college)|(mcm)|(mcmurtry)", "https://goo.gl/maps/bUfj3r4ooAm"],
["Janice and Robert McNair Hall", "(.*mcnair.*)|(mcn)", "https://goo.gl/maps/xbvGSC2u9gq"],
["Martel Center for Cont Studies", "(martel center for cont studies)|(mcs)", "https://goo.gl/maps/J1hnhYiVydJ2"], 
["Mechanical Engineering Bldg", "(mechanical engineering bldg)|(meb)", "https://goo.gl/maps/W68jhRG9Zn42"], 
["Media Center", "(media center)|(med)", "https://goo.gl/maps/bd97WVyMQpo"], 
["Mechanical Laboratory", "(mechanical laboratory)|(mel)", "https://goo.gl/maps/XCwQtshnjgs"], 
["Martel College", "(martel college)|(mlc)|(martel)", "https://goo.gl/maps/49K7eNMqhBF2"],
["S G Mudd Computer Science Lab", "(s g mudd computer science lab)|(.*mudd.*)", "https://goo.gl/maps/Qm9bLsEgUv52"],
["North Servery", "(north servery)|(nsv)|(north)", "https://goo.gl/maps/5agW4LkomU22"],
["Oshman Engineer Design Kitchen", "(oshman engineer design kitchen)|(oedk)", "https://goo.gl/maps/D93h8MtvXey"],
["Rice University Police Department", "(.*police.*)|(pol)|(rupd)", "https://goo.gl/maps/5kKwi9gp53S2"],
["Rice Children's Campus", "(rice children's campus)|(rcc)", "https://goo.gl/maps/kUGpmokVrEx"], 
["Reckling Park at Cameron Field", "(reckling park at cameron field)|(rck)", "https://goo.gl/maps/WsMJsD41aN82"], 
["Rice Graduate Apartments", "(rice graduate apartments)|(rga)", "https://goo.gl/maps/j6jAEtDUQ7T2"], 
["Rice Health and Wellness Cntr", "(rice health and wellness cntr)|(rhw)", "https://goo.gl/maps/gzJuEixXTZu"], 
["Rice Memorial Center", "(rice memorial center)|(rmc)", "https://goo.gl/maps/EuipxLCTrdp"], 
["Rice Village Apartments", "(rice village apartments)|(rva)", "https://goo.gl/maps/i5Md9yZNEPn"], 
["Ryon Engineering Laboratory", "(ryon engineering laboratory)|(ryn)", "https://goo.gl/maps/oQD8unXVkJo"], 
["Rayzor Hall", "(rayzor hall)|(rzr)|(rayzor)", "https://goo.gl/maps/DCvjNkpCE872"],
["Sewall Hall", "(sewall hall)|(sew)|(sewall)", "https://goo.gl/maps/zaHsCqqwe6p"],
["South Plant", "(south plant)|(spl)", "https://goo.gl/maps/dYqLh2DdN7J2"], 
["Sid Richardson College", "(sid richardson college)|(src)|(sid)|(sid rich)", "https://goo.gl/maps/YP5bYXohTCP2"],
["Space Science and Tech Bldg", "(space science and tech bldg)|(sst)", "https://goo.gl/maps/SJWfraBFJV42"], 
["South Servery", "(south servery)|(ssv)|(south)", "https://goo.gl/maps/BGGmY981uMx"],
["Rice Stadium", "(rice stadium)|(sta)", "https://goo.gl/maps/U2DX4dsA22n/"], 
["To Be Announced", "(to be announced)|(tba)", "a to-be-announced location."], 
["Tudor Fieldhouse", "(tudor fieldhouse)|(tud)|(tudor)", "https://goo.gl/maps/JfsuZKArcHr"],
["Wiess President's House", "(wiess president's house)|(wph)", "https://goo.gl/maps/wfZqjZVPChs"], 
["Will Rice College", "(will rice college)|(wrc)|(will rice)", "https://goo.gl/maps/AypESjPaey22"],
["Harry C Weiss College", "(harry c weiss college)|(wsc)|(wiess)|(weiss)", "https://goo.gl/maps/97Rx2gFEEbP2"],
["West Servery", "(west servery)|(wsv)|(west)", "https://goo.gl/maps/6kUsgQyi3h12"]];




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
     if (lastLoc[0].substr(0,9) == "conflict:") {
        // Execute the conflictMenu
        setUserDirectClarify(recipientId, true);
        console.log("clarification is " + getUser(recipientId).clarify);
        sendConflictMenu(recipientId, conflict[lastLoc[0].substr(9, lastLoc[0].length)]);
    } else {
         if (lastLoc[0].length <= 2) {
             sendTextMessage(recipientId, "I don't recognize that location. Please try again.");
         } else {
            sendTextMessage(recipientId, lastLoc[0] + " is located at " + lastLoc[1]);
         }
    }
}

/*
Helper function that takes in a list of possible conflict locations and sends them to the user.
 */
function sendConflictMenu(recipientId, conflictLists) {

    console.log("Checking conflicts, starting with" + conflictLists[0].toString());

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
                    "title":option[0].substr(0, 20),
                    "payload":option[0] + " is located at " + option[1]
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

    var explore = [
        ["The Frog Wall is a wall that sounds just like a frog chirping if you lick your thumb and run it down the wall.","http://content-img.newsinc.com/jpg/374/29570937/24703533.jpg?t=1439989620","https://goo.gl/maps/SpC9zE29evM2"],
        ["Rice has a piece of the historic Berlin wall on campus that divided Germany from 1961 to 1989.","http://mw2.google.com/mw-panoramio/photos/medium/66655372.jpg","https://goo.gl/maps/3pzPxMp9yYC2"],
        ["Duncan Hall, Rice's Computational Engineering Building, has an incredible ceiling inspired by many world cultures.","http://timeline.centennial.rice.edu/site_media/uploads/images/2011-03-24/Duncan_Hall_interior_copy_tif_800x700_q85.jpg","https://goo.gl/maps/M1VsyKEDrwq"],
        ["Skyspace is an art installation by James Turrell. It lights up different colors at night, and performances are held within it.","http://skyspace.rice.edu/site_media/media/cache/fb/6b/fb6b16ad6fc3576b29168317daacf4e2.png","https://goo.gl/maps/hrhCZW94hWt"]
    ];

    var rand = Math.floor(Math.random() * explore.length);

    //if we need to refresh array (all have been given to user)
    var arr = userState[recipientId].explore;
    if (arr.length >= explore.length) {
        userState[recipientId].explore = [];
        arr = [];
    }

    //while that explore has already been given
    while (contains(arr, rand)) {
        rand = Math.floor(Math.random() * explore.length);
    }

    //mark that this explore was given
    userState[recipientId].explore.push(rand);

    var imageMessage = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: explore[rand][1]
                }
            }
        }
    };

    callSendAPI(imageMessage);
    sendTextMessage(recipientId, explore[rand][0] + " Here's a Google Maps link: " + explore[rand][2]);
    setTimeout(function() {
        sendMenu(recipientId);
    }, 2000);
}

/*
 * Businesses and Serveries
 */
function sendBusiness(recipientId, messageData) {
    var businesses = [["Rice Coffeehouse is the student-run place to get your caffeine fix.", "(.*coffee.*)|(.*cafe.*)|(.*caffeine.*)", "https://goo.gl/maps/iDG2aGhfi4P2", "Mon-Thurs: 7:30am - 1am, Fri: 7:30am - 5pm, Sat: 10am - 5pm, Sun: 2pm - 1am"],
        ["The Hoot is Rice's late night food store", "(.*late.*)|(.*hoot.*)", "https://goo.gl/maps/EuipxLCTrdp", "Sunday — Wednesday 8:00 P.M. — 1:00 A.M, Thursday 8:00 P.M. — 1:30 A.M."],
        ["Rice Bookstore sells school supplies and Rice merchandise.", ".*book.*", "https://goo.gl/maps/EuipxLCTrdp", "Weekdays 8:00am - 6:00pm, Saturday 10:00am - 3:00pm, Sunday NOON - 4:00pm"],
        ["North Servery is one of Rice's serveries, serving Jones, Brown, and Martel colleges.", ".*north.*", "https://goo.gl/maps/5agW4LkomU22", "open for breakfast 7:30-10:30 every weekday, open for lunch 11:30-1:30 every weekday (11:30-2:00 on Sunday), and open for dinner 5:30-7:30 Monday through Thursday, 5:30-7:00 on Friday, and 5:00 - 7:00 on Sunday"],
        ["West Servery is one of Rice's serveries, serving McMurtry and Duncan colleges.", ".*west.*", "https://goo.gl/maps/sYYuo199NoE2", "open for breakfast 7:30-10:30 every weekday (9:00-11:00 on Saturday), open for lunch 11:30-1:30 every weekday (11:30-2:00 on weekends), and open for dinner 5:30-7:30 Monday through Thursday, 5:30-7:00 on Friday, and 5:00 - 7:00 on Sunday"],
        ["South Servery is one of Rice's serveries, serving Weiss and Hanszen colleges.", ".*south.*", "https://goo.gl/maps/BGGmY981uMx", "open for breakfast 7:30-10:30 every weekday, open for lunch 11:30-1:30 every weekday (11:30-2:00 on Sunday), and open for dinner 5:30-7:30 Monday through Thursday, 5:30-7:00 on Friday, and 5:00 - 7:00 on Sunday"],
        ["East-West boba tea is sold at West Servery.", ".*east.*", "https://goo.gl/maps/sYYuo199NoE2", "Tuesdays and Thursdays nights 8:30-10:30 pm"],
        ["Baker Servery is one of Rice's serveries, serving Baker college.", ".*baker.*", "https://goo.gl/maps/W5NJNnAFW2q", "weekdays from 7:30-10:30, 11:30-1:30, and 5:30-7:30 (no dinner on Fridays). Baker Kitchen is closed on weekends"],
        ["Seibel Servery is one of Rice's serveries, serving Lovett and Will Rice colleges.", "(.*seibel.*)|(.*siebel.*)", "https://goo.gl/maps/VXZo1RxHMHJ2", "open for breakfast 7:30-10:30 every weekday (9:00-11:00 on Saturday), open for lunch 11:30-1:30 every weekday (11:30-2:00 on weekends), and open for dinner 5:30-7:30 Monday through Thursday, 5:30-7:00 on Friday, and 5:00 - 7:00 on Sunday"],
        ["Sid Rich Servery is one of Rice's serveries, serving Sid Richardson college.", ".*sid.*", "https://goo.gl/maps/YP5bYXohTCP2", "open on weekdays from 7:30-10:30, 11:30-1:30, and 5:30-7:30 (no dinner on Fridays). Sid Kitchen is closed on weekends"]];

    var matches = [];
    businesses.forEach(function (location) {
        var reg = new RegExp(location[1]);
        if (reg.test(messageData) === true) {
            matches.push([location[0], location[2], location[3]]);
        }
    });
    var lastLoc = matches.length === 0 ? "Location not found." : matches[matches.length-1];
    if (lastLoc[0].length < 2) {
        sendTextMessage(recipientId, "I don't recognize that business, servery, or service. Please try again.");
        return;
    }
    sendTextMessage(recipientId, lastLoc[0]);
    setTimeout(function() {
        sendTextMessage(recipientId, "Their business hours are: " + lastLoc[2] + ".");
    }, 1500);
    setTimeout(function() {
        sendTextMessage(recipientId, "You can find them here: " + lastLoc[1]);
    }, 1500);
}

/*
 * Sends "about" page
 */
function sendAbout(recipientId) {

    sendTextMessage(recipientId, "I was made at HackRice 2016, Rice's hackathon. I'm unofficial and not affiliated with Rice's administration.");
}

/*
 * Sends "help" page
 */
function sendHelp(recipientId) {

    sendTextMessage(recipientId, "Try asking for directions \"Where's the library?\", or about a campus business \"coffee\". You can use the Explore and Fun Facts functions to find new places to explore, or learn about Rice.");
}

/*
 * Sends feedback prompt
 */
function sendFeedback(recipientId) {
    sendTextMessage(recipientId, "If you encounter a bug or want to send us some feedback, just include \"feedback\" somewhere in that message to the bot, and we'll see it. Thanks! We appreciate it!");
}

/*
 * Dumbledore! Ronnn Weasley! Harry Potter, Harry Potter, OOH!
 */
function sendEasterEgg(senderID) {
    var imageMessage = {
        recipient: {
            id: senderID
        },
        message: {
            attachment: {
                type: "image",
                payload: {
                    url: "http://i.imgur.com/3a9el.gif"
                }
            }
        }
    };

    callSendAPI(imageMessage);
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

