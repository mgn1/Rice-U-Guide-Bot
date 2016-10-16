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

var userState = {"john": {
    name:"menu",
    clarify:"false"
}};
/*
 * Get the state of the given user
 */
function getUserState(id) {
    return userState[id];
}
/*
 * Set the state of the given user
 */
function setUserState(id, newState) {
    userState[id].name = newState;
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

    if (getUserState(senderID) === undefined) {
        setUserState(senderID, "menu");
        setUserDirectClarify(senderID, false);

        console.log("undefined found. new state is " + getUserState(senderID).name);
    }

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (quickReply) {
      var quickReplyPayload = quickReply.payload;
      if (getUserState(senderID).clarify) {
        // TODO
      } else {
          setUserState(senderID, quickReplyPayload);
          sendTextMessage(senderID, quickReplyPayload + " selected as a quick reply. user: " + senderID +
              " state: " + getUserState(senderID).name);
      }
    return;
  }

  else if (messageText) {
      var state = getUserState(senderID).name;
      switch(state) {
          case "menu":
              sendMenu(senderID);
              break;
          case "directions":
              sendDirections(senderID, messageText);
              break;
          case "fun facts":
              sendFunFact(senderID);
              break;
          case "explore":
              sendTextMessage(senderID, "you are in explore");
              break;
          default:
              sendTextMessage(senderID, "wut did you do. state is "+ state);
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
  "Frogs are members of the order \"Anura\", and on wet nights you might find a bunch croaking around!"];

  sendTextMessage(recipientId, facts[Math.floor(Math.random() * facts.length)]);
}

/*
 * Sends directions
 */
function sendDirections(recipientId, messageData) {

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
        ]
    };

    conflict["Brown Hall"]

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
        ["Brown College", "brown(\\scollege)*"],
        ["Brown College Masters House", "brown(\\scollege)*(\\smaster)+.*(house)*"],
        ["conflict:Brown Hall", "brown\\shall"],
        ["Alice Pratt Brown Hall", "(((alice\\s)*(pratt\\s)+)|((alice\\s)+(pratt\\s)*))brown\\shall"],
        ["George R. Brown Hall", "(((george\\s)*(r\\.*\\s)+)|((george\\s)+(r\\.*\\s)*))brown\\shall"],
        ["Herman Brown Hall", "herman\\sbrown\\shall"]
    ];

    // Search for regexes
    var matches = [];
    locs.forEach(function (location) {
        var reg = new RegExp(location[1].toLowerCase());
        if (reg.test(messageData) == true) {
            matches.push(location[0]);
        }
    })

    var lastLoc = matches.length == 0 ? "Location not found." : matches[matches.length-1];

    console.log("Finished the matching: " + lastLoc);

    // Check if it is a conflict
    if (lastLoc.substr(0,9) == "conflict:") {
        // Execute the conflictMenu
        sendConflictMenu(recipientId, conflict[lastLoc.substr(9, lastLoc.length)])
    }

    // Return the highest result, and an error otherwise.
    sendTextMessage(recipientId, lastLoc);
}

function sendConflictMenu(recipientId, conflictLists) {

    setUserDirectClarify(recipientId, true);

    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: "Did you mean:",
            
            quick_replies: conflictLists.map(function (option) {
                return {
                    "content_type":"text",
                    "title":option,
                    "payload":option
                }
            })

        }
    };

    callSendAPI(messageData);
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

